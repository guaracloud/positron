#[cfg(feature = "test-support")]
use super::*;
#[cfg(feature = "test-support")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "test-support")]
struct MutableWallClock(Arc<Mutex<UnixNanoseconds>>);

#[cfg(feature = "test-support")]
impl crate::LifecycleClockSource for MutableWallClock {
    fn read(&self) -> Result<UnixNanoseconds, crate::LifecycleClockFailure> {
        self.0
            .lock()
            .map(|instant| *instant)
            .map_err(|_| crate::LifecycleClockFailure::Unavailable)
    }
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
    let (retention_time, elapsed) =
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

    elapsed.advance(5)?;
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
    assert_eq!(
        retention_time.status().safe_anchor(),
        UnixNanoseconds::new(200),
        "a rejected Catalog proposal must not leave its unpublished clock anchor live"
    );
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
        UnixNanoseconds::new(205)
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn normal_initial_frontier_publication_refuses_a_malformed_clock_anchor()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe7; 16])?,
        CatalogSecret::from_owned(Box::new([0xe8; 32]), Box::new([0xe9; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(44)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(500));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xeb; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0xea; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"PLIFCLK1\x02\x00".to_vec())?],
        )?,
        None,
    )?;
    let failure = match ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xec; 16])?,
    ) {
        Ok(_) => return Err("a malformed anchor was replaced by normal publication".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    assert!(
        catalog
            .pin()?
            .plaintext_objects()
            .any(|object| object == b"PLIFCLK1\x02\x00")
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn normal_initial_frontier_publication_refuses_duplicate_valid_clock_anchors()
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
    let scope_a = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(45)?);
    let scope_b = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(46)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(500));
    let ledger_a = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope_a,
        SegmentProtectionKey::from_owned(Box::new([0xf4; 32])),
    )?;
    drop(ledger_a.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xf5; 16])?,
    )?);
    let ledger_b = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope_b,
        SegmentProtectionKey::from_owned(Box::new([0xf6; 32])),
    )?;
    drop(ledger_b);
    let mut anchor = catalog
        .pin()?
        .plaintext_objects()
        .find(|object| object.starts_with(b"PLIFCLK1"))
        .ok_or("initial anchor was not published")?
        .to_vec();
    anchor[8] = 1;
    anchor.truncate(35);
    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .map(|object| CatalogObject::new(object.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(anchor)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf7; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;

    let generation_before_refusal = catalog.pin()?.number();
    let failure = match ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope_b,
        SegmentProtectionKey::from_owned(Box::new([0xf6; 32])),
    ) {
        Ok(_) => return Err("duplicate anchors were replaced by normal publication".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    assert_eq!(catalog.pin()?.number(), generation_before_refusal);
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|object| object.starts_with(b"PLIFCLK1"))
            .count(),
        2
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn uncertain_ingest_reconciles_a_durably_published_uncertain_clock_anchor()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd8; 16])?,
        CatalogSecret::from_owned(Box::new([0xd9; 32]), Box::new([0xda; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(13)?);
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(200)));
    let (retention_time, _) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableWallClock(Arc::clone(&wall)),
        crate::LifecycleClockPolicy::new(10)?,
    )?;
    *wall.lock().map_err(|_| "wall clock")? = UnixNanoseconds::new(1_000);
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xdb; 32])),
    )?;

    let prepared = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("capacity"),
                StoreBlockIdentity::new([0xdc; 16]).expect("identity"),
            )
        },
    )?;
    assert_eq!(prepared.scope(), scope);
    assert_eq!(
        retention_time.status().state(),
        crate::LifecycleClockState::ClockUncertain
    );
    Ok(())
}

#[cfg(feature = "test-support")]
fn catalog_backed_restart_fences_wall_clock_step(
    restarted_wall: UnixNanoseconds,
    discriminator: u8,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([discriminator; 16])?;
    let secret = || {
        CatalogSecret::from_owned(
            Box::new([discriminator.wrapping_add(1); 32]),
            Box::new([discriminator.wrapping_add(2); 32]),
        )
    };
    let catalog = Catalog::open(&authority, instance, secret())?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(14)?);
    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(200)));
    let (initial_time, _) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableWallClock(Arc::clone(&wall)),
        crate::LifecycleClockPolicy::new(10)?,
    )?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &initial_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([discriminator.wrapping_add(3); 32])),
    )?;
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([discriminator.wrapping_add(4); 16])?,
    )?;
    drop(preparation);
    assert!(
        catalog
            .pin()?
            .plaintext_objects()
            .any(|object| object.starts_with(b"PLIFCLK1")),
        "initial publication must persist the instance-wide lifecycle anchor"
    );
    drop(ledger);
    drop(catalog);

    *wall.lock().map_err(|_| "wall clock")? = restarted_wall;
    let recovered_catalog = Catalog::open(&authority, instance, secret())?;
    let (restarted_time, _) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableWallClock(Arc::clone(&wall)),
        crate::LifecycleClockPolicy::new(10)?,
    )?;
    let _reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &restarted_time,
        &recovered_catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([discriminator.wrapping_add(3); 32])),
    )?;

    assert_eq!(
        restarted_time.status().state(),
        crate::LifecycleClockState::ClockUncertain
    );
    assert!(restarted_time.ingest_time(scope, None).is_ok());
    assert_eq!(
        restarted_time.destructive_ingest_time(scope, None),
        Err(crate::LifecycleClockFailure::ClockUncertain)
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn catalog_backed_backward_restart_fences_retention_but_keeps_ingest_available()
-> Result<(), Box<dyn Error>> {
    catalog_backed_restart_fences_wall_clock_step(UnixNanoseconds::new(100), 0xb1)
}

#[cfg(feature = "test-support")]
#[test]
fn catalog_backed_forward_restart_fences_retention_but_keeps_ingest_available()
-> Result<(), Box<dyn Error>> {
    catalog_backed_restart_fences_wall_clock_step(UnixNanoseconds::new(1_000), 0xc1)
}

#[cfg(feature = "test-support")]
#[test]
fn uncertain_initial_frontier_fences_live_retries_until_reopen_recovers_the_marker()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xda; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([0xdb; 32]), Box::new([0xdc; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(30)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(400));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xdd; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let baseline = authority.governor().inspect()?;

    let failure = match with_ledger_fault(
        LedgerFileEvent::BeforeRetentionFrontierReconciliation,
        || {
            with_catalog_publication_fault_after(
                CatalogPublicationFault::SynchronizeGenerationDirectory,
                0,
                || {
                    ledger.begin_store_block(
                        preparation_capacity(&authority, tenant).expect("preparation capacity"),
                        StoreBlockIdentity::new([0xde; 16]).expect("block identity"),
                    )
                },
            )
        },
    ) {
        Ok(_) => return Err("unreconciled durable frontier was accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    let retry = match ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xdf; 16])?,
    ) {
        Ok(_) => return Err("frontier-uncertain live ledger accepted a retry".into()),
        Err(failure) => failure,
    };
    assert_eq!(retry.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(authority.governor().inspect()?, baseline);
    drop(ledger);
    drop(catalog);

    let recovered_catalog = Catalog::open(&authority, instance, secret())?;
    let recovered = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &recovered_catalog,
        scope,
        key(),
    )?;
    let recovered_generation = recovered_catalog.pin()?.number();
    let preparation = recovered.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe0; 16])?,
    )?;
    assert_eq!(
        preparation.ingest_time().instant(),
        UnixNanoseconds::new(400)
    );
    assert_eq!(recovered_catalog.pin()?.number(), recovered_generation);
    drop(preparation);
    assert_eq!(authority.governor().inspect()?, baseline);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn divergent_successor_after_ambiguous_initial_frontier_fences_the_live_ledger()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(43)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(500));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    let baseline = authority.governor().inspect()?;

    let failure = match with_catalog_generation_ambiguity_hook_after(
        0,
        |catalog| {
            catalog
                .refresh_after_ambiguous_publication_for_test()
                .expect("recover durable initial frontier");
            let basis = catalog.pin().expect("pin durable initial frontier");
            let objects = basis
                .plaintext_objects()
                .filter(|bytes| !bytes.starts_with(b"PLIFCLK1"))
                .map(|bytes| CatalogObject::new(bytes.to_vec()).expect("copy bounded object"))
                .collect::<Vec<_>>();
            catalog
                .commit(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([0xe5; 16]).expect("successor transaction"),
                        FormatEpoch::CATALOG_V1,
                        objects,
                    )
                    .expect("successor proposal"),
                    None,
                )
                .expect("publish divergent successor");
        },
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("preparation capacity"),
                StoreBlockIdentity::new([0xe6; 16]).expect("block identity"),
            )
        },
    ) {
        Ok(_) => return Err("divergent successor accepted the initial frontier".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    let fenced = match ledger.snapshot() {
        Ok(_) => return Err("post-marker divergence left snapshots available".into()),
        Err(failure) => failure,
    };
    assert_eq!(fenced.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(authority.governor().inspect()?, baseline);
    Ok(())
}
