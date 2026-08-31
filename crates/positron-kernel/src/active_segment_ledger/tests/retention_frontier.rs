use std::error::Error;
use std::num::NonZeroU64;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use super::support::{TemporaryRoot, establish_authority};
use crate::retention_time::RetentionTimeAuthority;
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch,
    InstanceId, LedgerFailureCode, MountQualification, PrimaryDataVolume, ResourceAmounts,
    ResourceDimension, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, TransactionId,
    WorkClaim, WorkKind,
};
#[cfg(feature = "test-support")]
use crate::{
    CatalogPublicationFault, RecoveryWorkClaim, RecoveryWorkKind,
    with_catalog_publication_fault_after,
};

#[test]
fn recovered_frontier_ignores_restart_wall_and_advances_only_by_new_monotonic_elapsed()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(9)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x94; 32]));
    let reserve = || -> Result<_, Box<dyn Error>> {
        Ok(authority.governor().reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?)
    };
    let (first_time, _first_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &first_time,
        &catalog,
        scope,
        key(),
    )?;
    let first = ledger.begin_store_block(reserve()?, StoreBlockIdentity::new([0x95; 16])?)?;
    let first_ingest = first.ingest_time();
    ledger.append(first.finish(b"first".to_vec())?)?;
    drop(ledger);

    let (restarted_time, restarted_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX / 2));
    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &restarted_time,
        &catalog,
        scope,
        key(),
    )?;
    let persisted_frontier_generation = catalog.pin()?.number();
    let after_restart =
        restarted.begin_store_block(reserve()?, StoreBlockIdentity::new([0x96; 16])?)?;
    assert_eq!(after_restart.ingest_time(), first_ingest);
    assert_eq!(catalog.pin()?.number(), persisted_frontier_generation);
    drop(after_restart);
    restarted_elapsed.advance(1_000_000_000)?;
    let advanced = restarted.begin_store_block(reserve()?, StoreBlockIdentity::new([0x97; 16])?)?;
    assert_eq!(
        advanced.ingest_time().instant().value(),
        first_ingest.instant().value() + 1_000_000_000
    );
    assert_eq!(catalog.pin()?.number(), persisted_frontier_generation);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn deterministic_test_ingest_time_cannot_authorize_retention() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let test_time = RetentionTimeAuthority::for_test_ingest_time(UnixNanoseconds::new(50));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &test_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(10)?),
        SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
    )?;

    let failure = match ledger.begin_retention(NonZeroU64::new(1).ok_or("duration")?) {
        Ok(_) => return Err("test-only Ingest Time authorized deletion".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn authenticated_malformed_and_duplicate_retention_frontiers_fail_closed_on_open()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )?;
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xb5; 16])?,
    )?;
    drop((preparation, ledger));
    let original = catalog
        .pin()?
        .plaintext_objects()
        .find(|bytes| bytes.starts_with(b"PRETFR01"))
        .ok_or("retention frontier missing")?
        .to_vec();

    let mut cases = Vec::new();
    cases.push((
        original.get(..38).ok_or("frontier length")?.to_vec(),
        LedgerFailureCode::UnsupportedFormat,
    ));
    let mut unknown_version = original.clone();
    unknown_version
        .get_mut(8..10)
        .ok_or("version field")?
        .copy_from_slice(&2_u16.to_be_bytes());
    cases.push((unknown_version, LedgerFailureCode::UnsupportedFormat));
    let mut invalid_tenant = original.clone();
    invalid_tenant
        .get_mut(10..26)
        .ok_or("tenant field")?
        .fill(0);
    cases.push((invalid_tenant, LedgerFailureCode::IntegrityCorruption));
    let mut invalid_signal = original.clone();
    *invalid_signal.get_mut(26).ok_or("signal field")? = 0;
    cases.push((invalid_signal, LedgerFailureCode::IntegrityCorruption));
    let mut invalid_shard = original.clone();
    invalid_shard.get_mut(27..31).ok_or("shard field")?.fill(0);
    cases.push((invalid_shard, LedgerFailureCode::IntegrityCorruption));

    for (index, (malformed, expected)) in cases.into_iter().enumerate() {
        replace_retention_frontier(
            &catalog,
            malformed,
            u8::try_from(index)
                .map_err(|_| "transaction index")?
                .saturating_add(0xc0),
        )?;
        let failure = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
        )
        .expect_err("authenticated malformed frontier must fence recovery");
        assert_eq!(failure.code(), expected);
    }

    let basis = catalog.pin()?;
    let mut objects = copied_non_frontier_objects(&basis)?;
    objects.push(CatalogObject::new(original.clone())?);
    let mut second = original;
    let instant = second.last_mut().ok_or("frontier instant")?;
    *instant ^= 1;
    objects.push(CatalogObject::new(second)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xcf; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let failure = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )
    .expect_err("duplicate authenticated frontiers must fence recovery");
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn retention_frontier_publication_reconciles_only_durable_ambiguity() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(12)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(200));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd4; 32])),
    )?;

    let preparation = preparation_capacity(&authority, tenant)?;
    let resources = authority.governor().inspect()?;
    let blocker_amount = resources
        .recovery_shared_capacity(ResourceDimension::MemoryBytes)
        .checked_sub(resources.usage(ResourceDimension::MemoryBytes))
        .and_then(|available| available.checked_sub(1))
        .ok_or("recovery capacity arithmetic overflow")?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, blocker_amount)?,
    )?)?;
    let generation_before_refusal = catalog.pin()?.number();
    let capacity_failure =
        match ledger.begin_store_block(preparation, StoreBlockIdentity::new([0xd5; 16])?) {
            Ok(_) => return Err("frontier publication proceeded without capacity".into()),
            Err(failure) => failure,
        };
    assert_eq!(
        capacity_failure.code(),
        LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(catalog.pin()?.number(), generation_before_refusal);
    drop(blocker);
    assert_eq!(
        authority.governor().inspect()?.recovery_pool_usage(
            RecoveryWorkKind::DurabilityCompletion,
            ResourceDimension::MemoryBytes,
        ),
        0
    );

    let rejected = match with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("capacity"),
                StoreBlockIdentity::new([0xd7; 16]).expect("identity"),
            )
        },
    ) {
        Ok(_) => return Err("pre-publication failure was accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(rejected.code(), LedgerFailureCode::StorageUnavailable);

    let reconciled = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("capacity"),
                StoreBlockIdentity::new([0xd6; 16]).expect("identity"),
            )
        },
    )?;
    assert_eq!(reconciled.scope(), scope);
    assert_eq!(reconciled.identity(), StoreBlockIdentity::new([0xd6; 16])?);
    assert_eq!(
        reconciled.ingest_time().instant(),
        UnixNanoseconds::new(200)
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn preparation_authority_rejects_wrong_capacity_and_production_time_substitution()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(13)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(300));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    let wrong_capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    let failure =
        match ledger.begin_store_block(wrong_capacity, StoreBlockIdentity::new([0xe5; 16])?) {
            Ok(_) => return Err("query capacity authorized ingest preparation".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);

    let failure = match ledger.begin_store_block_for_test(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe6; 16])?,
        &retention_time,
    ) {
        Ok(_) => return Err("production retention time entered test-only path".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);

    let test_time = RetentionTimeAuthority::for_test_ingest_time(UnixNanoseconds::new(301));
    let wrong_capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    let failure = match ledger.begin_store_block_for_test(
        wrong_capacity,
        StoreBlockIdentity::new([0xe7; 16])?,
        &test_time,
    ) {
        Ok(_) => return Err("query capacity authorized test preparation".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    Ok(())
}

#[test]
fn retention_bounds_and_pinned_evaluations_fail_closed_without_capacity_drift()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xf1; 16])?,
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(14)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(20_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf4; 32])),
    )?;

    let failure = match ledger.begin_retention(NonZeroU64::MAX) {
        Ok(_) => return Err("overflowing retention duration was admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);

    let prepared = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xf5; 16])?,
    )?;
    let stale_blocks = ledger.begin_retention(NonZeroU64::new(1).ok_or("duration")?)?;
    ledger.append(prepared.finish(b"later".to_vec())?)?;
    assert_eq!(
        stale_blocks
            .commit()
            .expect_err("evaluation must pin the inspected blocks")
            .code(),
        LedgerFailureCode::StaleGeneration
    );

    let stale_catalog = ledger.begin_retention(NonZeroU64::new(1).ok_or("duration")?)?;
    let basis = catalog.pin()?;
    let objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf6; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        stale_catalog
            .commit()
            .expect_err("evaluation must pin the catalog generation")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    Ok(())
}

#[test]
fn monotonic_overflow_and_cutoff_underflow_are_typed_public_refusals() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;

    let (overflow_time, overflow_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX));
    let overflow_scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(15)?);
    let overflow_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &overflow_time,
        &catalog,
        overflow_scope,
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    let initial = overflow_ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x74; 16])?,
    )?;
    assert_eq!(
        initial.ingest_time().instant(),
        UnixNanoseconds::new(i64::MAX)
    );
    drop(initial);
    overflow_elapsed.advance(1)?;
    let failure = match overflow_ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x75; 16])?,
    ) {
        Ok(_) => return Err("monotonic overflow minted Ingest Time".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    let failure = match overflow_ledger.begin_retention(NonZeroU64::new(1).ok_or("duration")?) {
        Ok(_) => return Err("monotonic overflow authorized retention".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    assert_eq!(
        format!("{overflow_time:?}"),
        "RetentionTimeAuthority { <monotonic> }"
    );

    let (minimum_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MIN));
    let minimum_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &minimum_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(16)?),
        SegmentProtectionKey::from_owned(Box::new([0x76; 32])),
    )?;
    let failure = match minimum_ledger.begin_retention(NonZeroU64::new(1).ok_or("duration")?) {
        Ok(_) => return Err("underflowing retention cutoff was admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    Ok(())
}

#[test]
fn sealed_nonempty_segment_expires_only_after_authoritative_elapsed_time()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x21; 16])?,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x23; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(17)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x24; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let prepared = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x25; 16])?,
    )?;
    sealed.append(prepared.finish(b"retained".to_vec())?)?;
    sealed.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let duration = NonZeroU64::new(1).ok_or("duration")?;
    let fresh = active.begin_retention(duration)?;
    assert_eq!(fresh.blocks().len(), 1);
    let fresh_outcome = fresh.commit()?;
    assert_eq!(fresh_outcome.logically_retired_segments(), 0);
    assert_eq!(fresh_outcome.physically_reclaimed_segments(), 0);

    elapsed.advance(2_000_000_000)?;
    let expired = active.begin_retention(duration)?;
    assert_eq!(
        expired.blocks().first().map(|block| block.payload()),
        Some(b"retained".as_slice()),
        "the expired evaluation must expose its pinned inspected block"
    );
    let outcome = expired.commit()?;
    assert_eq!(outcome.logically_retired_segments(), 1);
    assert_eq!(outcome.physically_reclaimed_segments(), 1);
    assert!(active.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn empty_sealed_segment_is_logically_retired_and_physically_reclaimed() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(17)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(2_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x34; 32]));
    ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?
    .seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let outcome = active
        .begin_retention(NonZeroU64::new(1).ok_or("duration")?)?
        .commit()?;
    assert_eq!(outcome.logically_retired_segments(), 1);
    assert_eq!(outcome.physically_reclaimed_segments(), 1);
    assert_eq!(outcome.evaluated_at(), UnixNanoseconds::new(2_000_000_000));
    assert!(active.snapshot()?.blocks().is_empty());
    drop(active);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert!(reopened.snapshot()?.blocks().is_empty());
    Ok(())
}

fn preparation_capacity<'kernel>(
    authority: &'kernel crate::StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<crate::ResourceReservation<'kernel>, Box<dyn Error>> {
    Ok(authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?)
}

#[cfg(feature = "test-support")]
fn copied_non_frontier_objects(
    basis: &crate::CatalogSnapshot,
) -> Result<Vec<CatalogObject>, Box<dyn Error>> {
    basis
        .plaintext_objects()
        .filter(|bytes| !bytes.starts_with(b"PRETFR01"))
        .map(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        .collect()
}

#[cfg(feature = "test-support")]
fn replace_retention_frontier(
    catalog: &Catalog<'_>,
    frontier: Vec<u8>,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = copied_non_frontier_objects(&basis)?;
    objects.push(CatalogObject::new(frontier)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
