use super::*;
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkClass, WorkKind};
use std::sync::atomic::{AtomicU64, Ordering};

struct CancelDuringDecode(AtomicU64);

impl super::super::ScanCancellation for CancelDuringDecode {
    fn is_cancelled(&self) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst) >= 4
    }
}

struct CancelDuringPreflight(AtomicU64);

impl super::super::ScanCancellation for CancelDuringPreflight {
    fn is_cancelled(&self) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst) >= 1
    }
}

struct CancelAfterPolls {
    polls: AtomicU64,
    threshold: u64,
}

impl CancelAfterPolls {
    const fn new(threshold: u64) -> Self {
        Self {
            polls: AtomicU64::new(0),
            threshold,
        }
    }
}

impl super::super::ScanCancellation for CancelAfterPolls {
    fn is_cancelled(&self) -> bool {
        self.polls.fetch_add(1, Ordering::SeqCst) >= self.threshold
    }
}

struct NeverCancelled;

impl super::super::ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct RecordingScanObserver(AtomicU64);

impl super::super::ScanObserver for RecordingScanObserver {
    fn observe_work(&self, units: u64) -> Result<(), super::super::ScanObservationFailureCode> {
        self.0.fetch_add(units, Ordering::SeqCst);
        Ok(())
    }
}

struct BudgetedScanObserver(AtomicU64);

impl super::super::ScanObserver for BudgetedScanObserver {
    fn observe_work(&self, units: u64) -> Result<(), super::super::ScanObservationFailureCode> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(units)
            })
            .map(|_| ())
            .map_err(|_| super::super::ScanObservationFailureCode::BudgetExhausted)
    }
}

#[test]
fn scan_is_bounded_and_refuses_another_physical_scope() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x13; 16])?,
        CatalogSecret::from_owned(Box::new([0x23; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let store = LogStore::new();
    let record = minimal_record("one", 1)?;
    let second = minimal_record("two", 2)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(3)?),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(1),
                tenant,
                VirtualShardId::new(3)?,
                StoreBlockIdentity::new([0x63; 16])?,
                vec![record.clone(), second],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let bounded = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(bounded.records().len(), 1);
    assert!(!bounded.complete());
    let wrong_tenant = store
        .scan(
            authority.governor(),
            TenantId::from_bytes([0x42; 16])?,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("a tenant cannot scan another physical tenant's snapshot");
    assert_eq!(
        wrong_tenant.code(),
        LogStoreFailureCode::PhysicalScopeMismatch
    );
    drop(ledger);

    let trace_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(4)?),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    trace_ledger.append(PreparedStoreBlock::new(
        SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(4)?),
        StoreBlockIdentity::new([0x64; 16])?,
        b"opaque-trace-block".to_vec(),
    )?)?;
    let wrong_signal = store
        .scan(
            authority.governor(),
            tenant,
            &trace_ledger.snapshot()?,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("Log Store cannot scan a Trace Store physical snapshot");
    assert_eq!(
        wrong_signal.code(),
        LogStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}

#[test]
fn sealed_and_successor_active_blocks_share_one_logical_scan() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x14; 16])?,
        CatalogSecret::from_owned(Box::new([0x24; 32]), Box::new([0x34; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(5)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let store = LogStore::new();
    let sealed_record = minimal_record("sealed", 10)?;
    let active_record = minimal_record("active", 11)?;
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(10),
                tenant,
                VirtualShardId::new(5)?,
                StoreBlockIdentity::new([0x65; 16])?,
                vec![sealed_record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let successor = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    successor.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(11),
                tenant,
                VirtualShardId::new(5)?,
                StoreBlockIdentity::new([0x66; 16])?,
                vec![active_record.clone()],
            )?
            .into_store_block(),
    )?;

    let result = store.scan(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        LogScan::all(ScanLimit::new(2)?),
    )?;
    assert_eq!(result.records()[0].record(), &sealed_record);
    assert_eq!(result.records()[1].record(), &active_record);
    assert!(result.complete());
    Ok(())
}

#[test]
fn a_store_block_is_atomic_for_the_decoded_record_budget() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x79; 16])?,
        CatalogSecret::from_owned(Box::new([0x7a; 32]), Box::new([0x7b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(79)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let records = (0..1_024)
        .map(|_| minimal_record("bounded", 1))
        .collect::<Result<Vec<_>, _>>()?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(123),
                tenant,
                shard,
                StoreBlockIdentity::new([0x7c; 16])?,
                records,
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let before = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(!result.complete());
    assert_eq!(result.decoded_records(), 1);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before + 1
    );
    drop(result);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );

    let recording = RecordingScanObserver(AtomicU64::new(0));
    let observed = LogStore::new().scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &recording,
    )?;
    assert!(
        recording.0.load(Ordering::SeqCst) >= 1_024,
        "every structurally validated tail record must be observed"
    );
    let exact_work = recording.0.load(Ordering::SeqCst);
    drop(observed);
    let exact = BudgetedScanObserver(AtomicU64::new(exact_work));
    let exact_result = LogStore::new().scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &exact,
    )?;
    assert_eq!(exact.0.load(Ordering::SeqCst), 0);
    drop(exact_result);
    let below = BudgetedScanObserver(AtomicU64::new(exact_work - 1));
    let failure = LogStore::new()
        .scan_observed(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &NeverCancelled,
            &below,
        )
        .expect_err("one less tail-validation work unit must fail closed");
    assert_eq!(failure.code(), LogStoreFailureCode::BudgetExhausted);

    for threshold in 1..=256 {
        let cancellation = CancelAfterPolls::new(threshold);
        let failure = LogStore::new()
            .scan_cancellable(
                authority.governor(),
                tenant,
                &snapshot,
                LogScan::all(ScanLimit::new(1)?),
                &cancellation,
            )
            .expect_err("every cancellation boundary must stop the oversized block");
        assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);
    }

    let exact = LogStore::new().scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1_024)?),
    )?;
    assert_eq!(exact.records().len(), 1_024);
    assert!(exact.complete());
    Ok(())
}

#[test]
fn oversized_block_preflight_has_an_exact_observed_work_boundary() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x7d; 16])?,
        CatalogSecret::from_owned(Box::new([0x7e; 32]), Box::new([0x7f; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(80)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x52; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(124),
                tenant,
                shard,
                StoreBlockIdentity::new([0x7d; 16])?,
                vec![minimal_record("first", 1)?, minimal_record("second", 2)?],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let scan = LogScan::all(ScanLimit::new(1)?);
    let recording = RecordingScanObserver(AtomicU64::new(0));
    let result = LogStore::new().scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        scan,
        &NeverCancelled,
        &recording,
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(!result.complete());
    drop(result);
    let exact_work = recording.0.load(Ordering::SeqCst);
    assert!(exact_work > 0);

    let exact = BudgetedScanObserver(AtomicU64::new(exact_work));
    let exact_result = LogStore::new().scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        scan,
        &NeverCancelled,
        &exact,
    )?;
    assert_eq!(exact_result.records().len(), 1);
    assert!(!exact_result.complete());
    assert_eq!(exact.0.load(Ordering::SeqCst), 0);
    drop(exact_result);

    let malformed_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(800)?);
    let malformed_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        malformed_scope,
        SegmentProtectionKey::from_owned(Box::new([0x62; 32])),
    )?;
    let mut malformed_payload = snapshot
        .blocks()
        .first()
        .ok_or("committed block missing")?
        .payload()
        .to_vec();
    malformed_payload.pop();
    malformed_ledger.append(PreparedStoreBlock::new(
        malformed_scope,
        StoreBlockIdentity::new([0x7e; 16])?,
        malformed_payload,
    )?)?;
    let malformed = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &malformed_ledger.snapshot()?,
            scan,
        )
        .expect_err("structurally malformed unretained tail must fail closed");
    assert_eq!(malformed.code(), LogStoreFailureCode::MalformedBlock);

    let before = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let exhausted = BudgetedScanObserver(AtomicU64::new(exact_work - 1));
    let failure = LogStore::new()
        .scan_observed(
            authority.governor(),
            tenant,
            &snapshot,
            scan,
            &NeverCancelled,
            &exhausted,
        )
        .expect_err("one less preflight work unit must fail without a prefix");
    assert_eq!(failure.code(), LogStoreFailureCode::BudgetExhausted);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    Ok(())
}

#[test]
fn fitting_block_decode_has_an_exact_observed_work_boundary() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x4d; 16])?,
        CatalogSecret::from_owned(Box::new([0x4e; 32]), Box::new([0x4f; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let profile = value_profile()?;
    let body = value(
        profile,
        CandidateAttributeValue::array((0..12).map(|_| CandidateAttributeValue::null()).collect()),
    )?;
    let record = LogRecord::checked_native(
        profile,
        EventTime::missing(),
        None,
        Some(body),
        vec![],
        LogMetadata::empty(),
        PolicyProvenance::new(1, [0x70; 32], vec![])?,
    )?;
    let shard = VirtualShardId::new(81)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(125),
                tenant,
                shard,
                StoreBlockIdentity::new([0x4d; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let scan = LogScan::all(ScanLimit::new(1)?);
    let recording = RecordingScanObserver(AtomicU64::new(0));
    let result = LogStore::new().scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        scan,
        &NeverCancelled,
        &recording,
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(result.complete());
    let exact_work = recording.0.load(Ordering::SeqCst);
    assert!(
        exact_work >= 15,
        "record, container, and nested values must each be observed"
    );
    drop(result);

    let exact = BudgetedScanObserver(AtomicU64::new(exact_work));
    let exact_result = LogStore::new().scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        scan,
        &NeverCancelled,
        &exact,
    )?;
    assert_eq!(exact_result.records().len(), 1);
    assert_eq!(exact.0.load(Ordering::SeqCst), 0);
    drop(exact_result);

    let before = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let exhausted = BudgetedScanObserver(AtomicU64::new(exact_work - 1));
    let failure = LogStore::new()
        .scan_observed(
            authority.governor(),
            tenant,
            &snapshot,
            scan,
            &NeverCancelled,
            &exhausted,
        )
        .expect_err("one less decode work unit must fail without a prefix");
    assert_eq!(failure.code(), LogStoreFailureCode::BudgetExhausted);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    Ok(())
}

#[test]
fn exact_result_limit_stops_before_decoding_a_later_committed_block() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x4a; 16])?,
        CatalogSecret::from_owned(Box::new([0x4b; 32]), Box::new([0x4c; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(74)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x4e; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &clock(1),
                tenant,
                shard,
                StoreBlockIdentity::new([0x4f; 16])?,
                vec![minimal_record("first", 1)?],
            )?
            .into_store_block(),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x50; 16])?,
        b"authenticated-but-not-a-log-block".to_vec(),
    )?)?;
    let snapshot = ledger.snapshot()?;
    let first_block_bytes = u64::try_from(
        snapshot
            .blocks()
            .first()
            .ok_or("first committed block missing")?
            .payload()
            .len(),
    )?;

    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;

    assert_eq!(result.records().len(), 1);
    assert!(!result.complete());
    assert_eq!(result.scanned_bytes(), first_block_bytes);
    Ok(())
}

#[test]
fn insufficient_query_budget_refuses_before_decode_and_releases_on_error()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x7d; 16])?,
        CatalogSecret::from_owned(Box::new([0x7e; 32]), Box::new([0x7f; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(80)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x7f; 16])?,
        b"malformed-but-authenticated".to_vec(),
    )?)?;
    let snapshot = ledger.snapshot()?;
    let baseline = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let claim = WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?;
    let mut saturation = Vec::new();
    while let Ok(grant) = authority.governor().reserve(claim) {
        saturation.push(grant);
    }
    let failure = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("query admission must precede malformed-block decoding");
    assert_eq!(
        failure.code(),
        LogStoreFailureCode::ResourceAdmissionRefused
    );
    drop(saturation);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    let malformed = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("malformed authenticated bytes fail closed");
    assert_eq!(malformed.code(), LogStoreFailureCode::MalformedBlock);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    Ok(())
}

#[test]
fn cancellable_scan_stops_during_snapshot_preflight_before_admission() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(82)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x64; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x65; 16])?,
        b"authenticated-preflight-block".to_vec(),
    )?)?;
    let snapshot = ledger.snapshot()?;
    let baseline = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let claim = WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?;
    let mut saturation = Vec::new();
    while let Ok(grant) = authority.governor().reserve(claim) {
        saturation.push(grant);
    }

    let failure = LogStore::new()
        .scan_cancellable(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &CancelDuringPreflight(AtomicU64::new(0)),
        )
        .expect_err("preflight cancellation must precede query admission");
    assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);

    drop(saturation);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    Ok(())
}

#[test]
fn cancellable_scan_stops_between_decoded_records_and_releases_capacity()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(81)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    for identity in [0x75_u8, 0x76] {
        ledger.append(
            LogStore::new()
                .prepare(
                    preparation_capacity(&authority, tenant)?,
                    &clock(i64::from(identity)),
                    tenant,
                    shard,
                    StoreBlockIdentity::new([identity; 16])?,
                    vec![minimal_record("cancel-me", i64::from(identity))?],
                )?
                .into_store_block(),
        )?;
    }
    let baseline = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);

    let failure = LogStore::new()
        .scan_cancellable(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            LogScan::all(ScanLimit::new(2)?),
            &CancelDuringDecode(AtomicU64::new(0)),
        )
        .expect_err("cancellation must interrupt bounded block decoding");
    assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    Ok(())
}
