use super::*;
use std::mem::size_of;

use crate::active_segment_ledger::SegmentRetention;
use crate::active_segment_ledger::retention_publication::retention_publication_claim;

#[test]
fn retention_publication_claim_covers_all_live_terminal_pair_buffers() -> Result<(), Box<dyn Error>>
{
    let claim = retention_publication_claim()?;
    let scanned_metadata = crate::catalog::MAX_CATALOG_OBJECTS
        .checked_mul(size_of::<
            crate::active_segment_ledger::format::SegmentMetadata,
        >())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("scanned metadata bound")?;
    let proposed_catalog = crate::catalog::MAX_CATALOG_OBJECTS
        .checked_mul(size_of::<CatalogObject>())
        .and_then(|objects| {
            crate::catalog::MAX_CATALOG_OBJECTS
                .checked_mul(size_of::<
                    crate::active_segment_ledger::format::SegmentMetadata,
                >())
                .and_then(|metadata| objects.checked_add(metadata))
        })
        .ok_or("proposed catalog bound")?;
    let record = crate::maintenance::retention_publication_record_bytes_bound()
        .expect("bounded Retention Publication record encoding");
    let expected = crate::catalog::MAX_CATALOG_TOTAL_BYTES
        .checked_add(scanned_metadata.max(proposed_catalog))
        .and_then(|bytes| {
            bytes.checked_add(
                11_usize
                    .checked_mul(16)
                    .and_then(|count| count.checked_mul(size_of::<crate::MaintenanceObjectId>()))?,
            )
        })
        .and_then(|bytes| bytes.checked_add(4_usize.checked_mul(record)?))
        .and_then(|bytes| bytes.checked_add(3_usize.checked_mul(4_096)?))
        .ok_or("retention publication live-buffer bound")?;
    assert_eq!(
        claim.get(ResourceDimension::MemoryBytes),
        u64::try_from(expected)?,
        "the execution claim must cover persistent, dispatched, planned, and terminal-pair bindings; three checkpoint vectors; and four simultaneous encoded/Catalog task records"
    );
    Ok(())
}

#[test]
fn retention_publication_requires_its_exact_recovery_headroom_before_planning()
-> Result<(), Box<dyn Error>> {
    let claim = retention_publication_claim()?;
    let exact_root = TemporaryRoot::new()?;
    let exact_volume =
        PrimaryDataVolume::acquire(exact_root.path(), MountQualification::LocalHost)?;
    let exact_authority = establish_authority_with_retention_capacity(exact_volume, claim)?;
    let exact_instance = InstanceId::new([0x31; 16])?;
    let exact_catalog = Catalog::open(
        &exact_authority,
        exact_instance,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&exact_catalog, exact_instance, tenant, 1, 0x34)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(105)?);
    let (exact_time, exact_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x35; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &exact_authority,
        &exact_time,
        &exact_catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&exact_authority, tenant)?,
        StoreBlockIdentity::new([0x36; 16])?,
    )?;
    sealed.append(block.finish(b"exact retention publication claim".to_vec())?)?;
    sealed.seal()?;
    exact_elapsed.advance(2_000_000_000)?;
    let exact = ActiveSegmentLedger::open_with_retention_time(
        &exact_authority,
        &exact_time,
        &exact_catalog,
        scope,
        key(),
    )?;
    let exact_shared = recovery_shared_capacity(&exact_authority)?;
    let _exact_shared_blocker = exact_authority
        .recovery()
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            exact_shared,
        )?)?;
    let preparation = exact
        .prepare_retention_publication()
        .expect("the exact derived claim must be admitted");
    assert_eq!(preparation.task().reservations(), claim);
    drop(preparation);

    let below = ResourceAmounts::new([
        claim
            .get(ResourceDimension::MemoryBytes)
            .checked_sub(1)
            .ok_or("retention publication claim must charge memory")?,
        claim.get(ResourceDimension::QueueSlots),
        claim.get(ResourceDimension::TaskSlots),
        claim.get(ResourceDimension::BufferCacheBytes),
        claim.get(ResourceDimension::BatchItems),
        claim.get(ResourceDimension::LeaseSlots),
        claim.get(ResourceDimension::RetrySlots),
        claim.get(ResourceDimension::IoPermits),
        claim.get(ResourceDimension::CpuWorkUnits),
        claim.get(ResourceDimension::FileDescriptors),
        claim.get(ResourceDimension::DiskHeadroomBytes),
    ]);
    let below_root = TemporaryRoot::new()?;
    let below_volume =
        PrimaryDataVolume::acquire(below_root.path(), MountQualification::LocalHost)?;
    let below_authority = establish_authority_with_retention_capacity(below_volume, below)?;
    assert_eq!(
        below_authority
            .governor()
            .inspect()?
            .recovery_pool_capacity(
                crate::RecoveryWorkKind::Retention,
                ResourceDimension::MemoryBytes,
            ),
        below.get(ResourceDimension::MemoryBytes),
        "the test must configure exactly one byte less publication headroom"
    );
    let below_instance = InstanceId::new([0x41; 16])?;
    let below_catalog = Catalog::open(
        &below_authority,
        below_instance,
        CatalogSecret::from_owned(Box::new([0x42; 32]), Box::new([0x43; 32])),
    )?;
    install_governance_policy(&below_catalog, below_instance, tenant, 1, 0x44)?;
    let below_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(106)?);
    let (below_time, below_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let below_key = || SegmentProtectionKey::from_owned(Box::new([0x45; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &below_authority,
        &below_time,
        &below_catalog,
        below_scope,
        below_key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&below_authority, tenant)?,
        StoreBlockIdentity::new([0x46; 16])?,
    )?;
    sealed.append(block.finish(b"refuse before malformed retention metadata".to_vec())?)?;
    sealed.seal()?;
    below_elapsed.advance(2_000_000_000)?;
    let below = ActiveSegmentLedger::open_with_retention_time(
        &below_authority,
        &below_time,
        &below_catalog,
        below_scope,
        below_key(),
    )?;
    let below_shared = recovery_shared_capacity(&below_authority)?;
    let _below_shared_blocker = below_authority
        .recovery()
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::DurabilityCompletion,
            below_shared,
        )?)?;
    below
        .state
        .lock()
        .expect("ledger state")
        .blocks
        .first_mut()
        .expect("retention block")
        .block_retention = SegmentRetention::Unavailable;
    let failure = below
        .prepare_retention_publication()
        .expect_err("one byte below the derived claim must refuse before planning");
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    Ok(())
}

fn recovery_shared_capacity(
    authority: &crate::StorageKernelResourceAuthority,
) -> Result<ResourceAmounts, Box<dyn Error>> {
    let inspection = authority.governor().inspect()?;
    Ok(ResourceAmounts::new([
        available_shared(&inspection, ResourceDimension::MemoryBytes)?,
        available_shared(&inspection, ResourceDimension::QueueSlots)?,
        available_shared(&inspection, ResourceDimension::TaskSlots)?,
        available_shared(&inspection, ResourceDimension::BufferCacheBytes)?,
        available_shared(&inspection, ResourceDimension::BatchItems)?,
        available_shared(&inspection, ResourceDimension::LeaseSlots)?,
        available_shared(&inspection, ResourceDimension::RetrySlots)?,
        available_shared(&inspection, ResourceDimension::IoPermits)?,
        available_shared(&inspection, ResourceDimension::CpuWorkUnits)?,
        available_shared(&inspection, ResourceDimension::FileDescriptors)?,
        available_shared(&inspection, ResourceDimension::DiskHeadroomBytes)?,
    ]))
}

fn available_shared(
    inspection: &crate::ResourceSnapshot,
    dimension: ResourceDimension,
) -> Result<u64, Box<dyn Error>> {
    inspection
        .recovery_shared_capacity(dimension)
        .checked_sub(inspection.usage(dimension))
        .ok_or_else(|| "existing usage exceeded recovery shared capacity".into())
}
