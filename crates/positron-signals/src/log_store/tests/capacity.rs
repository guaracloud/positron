use std::sync::atomic::{AtomicUsize, Ordering};

use positron_kernel::{
    LifecycleClockFailure, LifecycleClockSource, ReleaseOutcome, ResourceDimension, WorkClass,
};

use super::*;

const MAX_BLOCK_BYTES: usize = 1_048_576;

#[test]
fn preparation_accepts_exact_block_maximum_and_rejects_the_next_byte_without_clock_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let reads = AtomicUsize::new(0);
    let clock = LifecycleClock::new(CountingClock { reads: &reads });
    let baseline = authority.governor().inspect()?;

    let prepared = LogStore::new().prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &clock,
        tenant,
        VirtualShardId::new(81)?,
        StoreBlockIdentity::new([0x81; 16])?,
        sized_records(261_692)?,
    )?;
    assert_eq!(reads.load(Ordering::Relaxed), 4);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        baseline.usage(ResourceDimension::MemoryBytes) + MAX_BLOCK_BYTES as u64
    );
    drop(prepared);
    assert_accounting(&authority, baseline)?;

    reads.store(0, Ordering::Relaxed);
    let failure = LogStore::new()
        .prepare_unretained_for_test(
            preparation_capacity(&authority, tenant)?,
            &clock,
            tenant,
            VirtualShardId::new(82)?,
            StoreBlockIdentity::new([0x82; 16])?,
            sized_records(261_693)?,
        )
        .err()
        .ok_or("the first byte beyond the Store Block maximum unexpectedly prepared")?;
    assert_eq!(failure.code(), LogStoreFailureCode::LimitExceeded);
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_accounting(&authority, baseline)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(82)?),
        SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
    )?;
    let snapshot = ledger.snapshot()?;
    assert_eq!(
        snapshot.frontier(),
        positron_domain::routing::CommitPosition::origin()
    );
    assert!(snapshot.blocks().is_empty());
    Ok(())
}

#[test]
fn cancelled_preparation_capacity_is_refused_before_clock_or_allocation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let reads = AtomicUsize::new(0);
    let clock = LifecycleClock::new(CountingClock { reads: &reads });
    let baseline = authority.governor().inspect()?;

    for marker in [0x91, 0x92] {
        let mut capacity = preparation_capacity(&authority, tenant)?;
        assert_eq!(capacity.cancel()?, ReleaseOutcome::Released);
        let failure = LogStore::new()
            .prepare_unretained_for_test(
                capacity,
                &clock,
                tenant,
                VirtualShardId::new(u32::from(marker))?,
                StoreBlockIdentity::new([marker; 16])?,
                sized_records(261_876)?,
            )
            .err()
            .ok_or("cancelled capacity unexpectedly prepared a Store Block")?;
        assert_eq!(
            failure.code(),
            LogStoreFailureCode::ResourceAdmissionRefused
        );
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        assert_accounting(&authority, baseline)?;
    }
    Ok(())
}

#[test]
fn preparation_capacity_is_continuous_through_commit_and_every_terminal_path()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x83; 16])?,
        CatalogSecret::from_owned(Box::new([0x84; 32]), Box::new([0x85; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(83)?;
    let empty = authority.governor().inspect()?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x86; 32])),
    )?;
    let baseline = authority.governor().inspect()?;
    let record = minimal_record("accounted", 1)?;
    let prepared = LogStore::new().prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &clock(1),
        tenant,
        shard,
        StoreBlockIdentity::new([0x87; 16])?,
        vec![record.clone()],
    )?;
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::Ingest),
        baseline.outstanding_for(WorkClass::Ingest) + 1
    );
    ledger.append(prepared.into_store_block())?;
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::Ingest),
        baseline.outstanding_for(WorkClass::Ingest)
    );
    ledger.seal()?;
    assert_accounting(&authority, empty)?;

    let other_shard = VirtualShardId::new(84)?;
    let other = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, other_shard),
        SegmentProtectionKey::from_owned(Box::new([0x88; 32])),
    )?;
    let other_baseline = authority.governor().inspect()?;
    let wrong_scope = LogStore::new()
        .prepare_unretained_for_test(
            preparation_capacity(&authority, tenant)?,
            &clock(2),
            tenant,
            shard,
            StoreBlockIdentity::new([0x89; 16])?,
            vec![record],
        )?
        .into_store_block();
    assert!(other.append(wrong_scope).is_err());
    assert_accounting(&authority, other_baseline)?;
    let snapshot = other.snapshot()?;
    assert_eq!(
        snapshot.frontier(),
        positron_domain::routing::CommitPosition::origin()
    );
    assert!(snapshot.blocks().is_empty());
    Ok(())
}

#[test]
fn append_refuses_preparation_capacity_from_another_governor_without_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let foreign_root = TemporaryRoot::new()?;
    let foreign_volume =
        PrimaryDataVolume::acquire(foreign_root.path(), MountQualification::LocalHost)?;
    let foreign_authority = establish_kernel_authority(foreign_volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(85)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa4; 32])),
    )?;
    let ledger_baseline = authority.governor().inspect()?;
    let foreign_baseline = foreign_authority.governor().inspect()?;
    let block = PreparedStoreBlock::new_with_preparation_capacity(
        scope,
        StoreBlockIdentity::new([0xa5; 16])?,
        vec![1],
        preparation_capacity(&foreign_authority, tenant)?,
    )?;

    let failure = ledger
        .append(block)
        .expect_err("capacity from another governor cannot authorize append");
    assert_eq!(
        failure.code(),
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_accounting(&authority, ledger_baseline)?;
    assert_accounting(&foreign_authority, foreign_baseline)?;
    let snapshot = ledger.snapshot()?;
    assert_eq!(
        snapshot.frontier(),
        positron_domain::routing::CommitPosition::origin()
    );
    assert!(snapshot.blocks().is_empty());
    Ok(())
}

fn sized_records(last_body_bytes: usize) -> Result<Vec<LogRecord>, Box<dyn Error>> {
    let policy = PolicyProvenance::new(1, [0x90; 32], vec![])?;
    [262_144, 262_144, 262_144, last_body_bytes]
        .into_iter()
        .map(|bytes| {
            LogRecord::checked_minimal(None, Some("x".repeat(bytes)), vec![], policy.clone())
                .map_err(Into::into)
        })
        .collect()
}

fn assert_accounting(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    expected: positron_kernel::ResourceSnapshot,
) -> Result<(), Box<dyn Error>> {
    let actual = authority.governor().inspect()?;
    assert_eq!(
        actual.outstanding_for(WorkClass::Ingest),
        expected.outstanding_for(WorkClass::Ingest)
    );
    assert_eq!(
        actual.usage(ResourceDimension::MemoryBytes),
        expected.usage(ResourceDimension::MemoryBytes)
    );
    Ok(())
}

struct CountingClock<'a> {
    reads: &'a AtomicUsize,
}

impl LifecycleClockSource for CountingClock<'_> {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(UnixNanoseconds::new(123))
    }
}
