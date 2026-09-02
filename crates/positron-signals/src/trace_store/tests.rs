use super::{SamplingDecision, SpanKind, SpanObservation, StoredSpanObservation, codec};
use super::{TraceScan, TraceStore};
use crate::{
    ScanCancellation, ScanLimit, ScanObservationFailureCode, ScanObserver, TraceStoreFailureCode,
};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
    CandidateKeyValue, ValueLimitProfile,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, GovernorPolicy,
    InstanceId, LifecycleClock, MountQualification, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPoolPolicy, OwnedPrimaryDataVolume, PrimaryDataVolume, RecoveryPoolCapacities,
    RecoveryReserve, RegisteredResourceBounds, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, SegmentProtectionKey, SegmentScope,
    StorageKernelResourceAuthority, TenantQuota, WorkClaim, WorkKind,
};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-trace-store-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_native_span_observation_preserves_its_identity_and_sampling_state() {
    let observation = SpanObservation::checked_minimal(
        [0x11; 16],
        [0x22; 8],
        None,
        "checkout".to_owned(),
        Some(10),
        Some(20),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
    )
    .expect("valid native span");

    assert_eq!(observation.trace_id(), [0x11; 16]);
    assert_eq!(observation.span_id(), [0x22; 8]);
    assert_eq!(observation.parent_span_id(), None);
    assert_eq!(observation.name(), "checkout");
    assert_eq!(observation.kind(), SpanKind::Server);
    assert_eq!(observation.sampling(), SamplingDecision::Sampled);
    assert_eq!(
        observation
            .start_time()
            .instant()
            .map(|value| value.value()),
        Some(10)
    );
    assert_eq!(
        observation.end_time().instant().map(|value| value.value()),
        Some(20)
    );
    let zero_time = SpanObservation::checked_minimal(
        [0x12; 16],
        [0x23; 8],
        None,
        "zero-time".to_owned(),
        Some(0),
        Some(0),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
    )
    .expect("zero source timestamps remain explicitly non-usable");
    assert_eq!(
        zero_time.start_time().quality(),
        positron_domain::time::SourceTimeQuality::Zero
    );
}

#[test]
fn native_span_identity_and_name_bounds_fail_closed() {
    let zero_trace = SpanObservation::checked_minimal(
        [0; 16],
        [0x22; 8],
        None,
        "span".to_owned(),
        None,
        None,
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
    )
    .expect_err("zero trace IDs are not native identities");
    assert_eq!(zero_trace.code(), TraceStoreFailureCode::InvalidInput);

    let empty_name = SpanObservation::checked_minimal(
        [0x11; 16],
        [0x22; 8],
        Some([0; 8]),
        String::new(),
        None,
        None,
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
    )
    .expect_err("empty names and zero parents are not native observations");
    assert_eq!(empty_name.code(), TraceStoreFailureCode::InvalidInput);
}

#[test]
fn committed_span_is_visible_immediately_from_the_active_segment() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x13; 16])?,
        CatalogSecret::from_owned(Box::new([0x23; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(3)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    let observation = SpanObservation::checked_minimal(
        [0x11; 16],
        [0x22; 8],
        None,
        "checkout".to_owned(),
        Some(10),
        Some(20),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
    )?;
    let store = TraceStore::new();
    let block = store.prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x63; 16])?,
        vec![observation.clone()],
    )?;
    let receipt = ledger.append(block.into_store_block())?;
    let marker = receipt.position();
    let ordinal = positron_domain::routing::RecordOrdinal::new(0)?;
    let through = TraceScan::through(ScanLimit::new(1)?, marker);
    assert_eq!(through.limit().value(), 1);
    assert_eq!(through.frontier(), Some(marker));
    assert_eq!(through.after_position(), None);
    let after = TraceScan::after(ScanLimit::new(1)?, marker);
    assert_eq!(after.after_position(), Some(marker));
    assert_eq!(after.frontier(), None);
    let between = TraceScan::between(ScanLimit::new(1)?, marker, marker);
    assert_eq!(between.after_position(), Some(marker));
    assert_eq!(between.frontier(), Some(marker));
    let between_record = TraceScan::between_record(ScanLimit::new(1)?, marker, ordinal, marker)
        .with_scanned_bytes(1);
    assert_eq!(between_record.after_record(), Some((marker, ordinal)));
    assert_eq!(between_record.scanned_bytes_limit(), Some(1));
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.observations().len(), 1);
    assert!(result.complete());
    assert_eq!(result.incompleteness(), super::TraceIncompleteness::None);
    assert_eq!(result.observations()[0].observation(), &observation);
    assert_eq!(
        result.observations()[0].commit_position(),
        receipt.position()
    );
    assert_eq!(result.decoded_observations(), 1);
    assert!(result.scanned_bytes() > 0);
    assert!(!result.scanned_bytes_limited());
    assert!(result.retained_size_bytes() >= 512);
    assert_eq!(
        result.observations()[0].stored().observation(),
        &observation
    );
    assert_eq!(result.observations()[0].trace_id(), observation.trace_id());
    assert_eq!(result.observations()[0].span_id(), observation.span_id());
    assert_eq!(
        result.observations()[0].ingest_time().instant().value(),
        100
    );
    let owned = result.into_observations();
    assert_eq!(owned.len(), 1);
    drop(ledger);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert!(restarted.complete());
    assert_eq!(restarted.observations()[0].observation(), &observation);

    let limited = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(0),
    )?;
    assert!(limited.observations().is_empty());
    assert!(!limited.complete());
    assert_eq!(
        limited.incompleteness(),
        super::TraceIncompleteness::ScannedBytesLimit
    );
    drop(limited);

    let after_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after(ScanLimit::new(1)?, marker),
    )?;
    assert!(after_result.observations().is_empty());
    assert!(after_result.complete());
    let through_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::through(ScanLimit::new(1)?, marker),
    )?;
    assert_eq!(through_result.observations().len(), 1);
    let between_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::between(ScanLimit::new(1)?, marker, marker),
    )?;
    assert!(between_result.observations().is_empty());

    for (observer, expected) in [
        (
            &WorkBudgetExhausted as &dyn ScanObserver,
            TraceStoreFailureCode::BudgetExhausted,
        ),
        (
            &BytesBudgetExhausted as &dyn ScanObserver,
            TraceStoreFailureCode::BudgetExhausted,
        ),
        (
            &RecordsBudgetExhausted as &dyn ScanObserver,
            TraceStoreFailureCode::BudgetExhausted,
        ),
    ] {
        let failure = store
            .scan_observed(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
                &NeverCancelled,
                observer,
            )
            .expect_err("observer budget failures must remain typed");
        assert_eq!(failure.code(), expected);
    }

    let before_cancel = authority.governor().inspect()?;
    let cancellation = AlwaysCancelled;
    let failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
            &cancellation,
            &NeverObserved,
        )
        .expect_err("cancelled trace scan must stop before resource admission");
    assert_eq!(failure.code(), TraceStoreFailureCode::Cancelled);
    let after_cancel = authority.governor().inspect()?;
    assert_eq!(
        after_cancel.outstanding_total(),
        before_cancel.outstanding_total()
    );

    let small_amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?;
    let refused_capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        small_amounts,
    )?)?;
    let admission_failure = store
        .prepare_unretained_for_test(
            refused_capacity,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
            tenant,
            shard,
            positron_kernel::StoreBlockIdentity::new([0x72; 16])?,
            vec![observation.clone()],
        )
        .err()
        .ok_or("insufficient preparation capacity was unexpectedly accepted")?;
    assert_eq!(
        admission_failure.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );

    let too_many = match store.prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x73; 16])?,
        vec![observation; 1_025],
    ) {
        Ok(_) => return Err("Trace Store accepted too many observations".into()),
        Err(failure) => failure,
    };
    assert_eq!(too_many.code(), TraceStoreFailureCode::LimitExceeded);
    Ok(())
}

#[test]
fn trace_scan_enforces_physical_tenant_and_signal_boundaries() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x14; 16])?,
        CatalogSecret::from_owned(Box::new([0x24; 32]), Box::new([0x34; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(4)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    let block = TraceStore::new().prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x64; 16])?,
        vec![SpanObservation::checked_minimal(
            [0x11; 16],
            [0x22; 8],
            None,
            "server".to_owned(),
            None,
            None,
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
        )?],
    )?;
    ledger.append(block.into_store_block())?;
    let snapshot = ledger.snapshot()?;
    let wrong_tenant = TraceStore::new()
        .scan(
            authority.governor(),
            TenantId::from_bytes([0x42; 16])?,
            &snapshot,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("cross-tenant trace scan must fail closed");
    assert_eq!(
        wrong_tenant.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    let logs_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(10)?);
    let logs_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        logs_scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let wrong_signal = TraceStore::new()
        .scan(
            authority.governor(),
            tenant,
            &logs_ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("cross-signal trace scan must fail closed");
    assert_eq!(
        wrong_signal.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}

#[test]
fn sealed_and_successor_active_segments_have_equivalent_trace_scan_visibility()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x15; 16])?,
        CatalogSecret::from_owned(Box::new([0x25; 32]), Box::new([0x35; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(5)?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let first = SpanObservation::checked_minimal(
        [0x11; 16],
        [0x22; 8],
        None,
        "sealed".to_owned(),
        Some(10),
        None,
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
    )?;
    let second = SpanObservation::checked_minimal(
        [0x11; 16],
        [0x23; 8],
        Some([0x22; 8]),
        "active".to_owned(),
        Some(11),
        Some(12),
        Vec::new(),
        SpanKind::Client,
        SamplingDecision::NotSampled,
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        key(),
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x65; 16])?,
                vec![first.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let successor = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        key(),
    )?;
    successor.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x66; 16])?,
                vec![second.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &successor.snapshot()?,
        TraceScan::all(ScanLimit::new(2)?),
    )?;
    assert!(result.complete());
    assert_eq!(
        result
            .observations()
            .iter()
            .map(|observation| observation.observation().name())
            .collect::<Vec<_>>(),
        vec!["sealed", "active"]
    );
    Ok(())
}

#[test]
fn physical_observations_are_not_deduplicated_at_the_storage_seam() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x16; 16])?,
        CatalogSecret::from_owned(Box::new([0x26; 32]), Box::new([0x36; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(6)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    let observation = SpanObservation::checked_minimal(
        [0x31; 16],
        [0x32; 8],
        None,
        "retry".to_owned(),
        Some(10),
        Some(20),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
    )?;
    let conflict = SpanObservation::checked_minimal(
        [0x31; 16],
        [0x32; 8],
        None,
        "conflicting-retry".to_owned(),
        Some(10),
        Some(20),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
    )?;
    let store = TraceStore::new();
    let receipt = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x67; 16])?,
                vec![observation.clone(), observation.clone(), conflict.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    assert_eq!(result.observations().len(), 3);
    assert_eq!(
        result.observations()[0].observation(),
        result.observations()[1].observation()
    );
    assert_eq!(
        result.observations()[0].record_ordinal(),
        positron_domain::routing::RecordOrdinal::new(0)?
    );
    assert_eq!(
        result.observations()[1].record_ordinal(),
        positron_domain::routing::RecordOrdinal::new(1)?
    );
    assert_eq!(result.observations()[2].observation(), &conflict);
    let resumed = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::between_record(
            ScanLimit::new(2)?,
            receipt.position(),
            positron_domain::routing::RecordOrdinal::new(0)?,
            receipt.position(),
        ),
    )?;
    assert!(resumed.complete());
    assert_eq!(resumed.observations().len(), 2);
    assert_eq!(resumed.observations()[0].record_ordinal().value(), 1);
    assert_eq!(resumed.observations()[1].record_ordinal().value(), 2);
    assert_eq!(resumed.observations()[1].observation(), &conflict);
    Ok(())
}

#[test]
fn bounded_trace_scan_reports_explicit_result_incompleteness() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x17; 16])?,
        CatalogSecret::from_owned(Box::new([0x27; 32]), Box::new([0x37; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(7)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )?;
    let store = TraceStore::new();
    let observations = (0_u8..3)
        .map(|id| {
            SpanObservation::checked_minimal(
                [0x41; 16],
                [id.saturating_add(1); 8],
                None,
                format!("span-{id}"),
                None,
                None,
                Vec::new(),
                SpanKind::Internal,
                SamplingDecision::Unknown,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x68; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.observations().len(), 1);
    assert!(!result.complete());
    assert_eq!(
        result.incompleteness(),
        super::TraceIncompleteness::ResultLimit
    );
    Ok(())
}

#[test]
fn trace_blocks_round_trip_native_typed_values_and_missing_times() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(8)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let profile = TraceStore::value_limit_profile();
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Resource,
            "http.status_code".to_owned(),
            vec![CandidateAttributeValue::signed_integer(200)],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "sampled".to_owned(),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "nothing".to_owned(),
            vec![CandidateAttributeValue::null()],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "ratio".to_owned(),
            vec![CandidateAttributeValue::floating_point_bits(
                0x3ff0_0000_0000_0000,
            )],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![CandidateAttributeValue::bytes(vec![1, 2, 3])],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "array".to_owned(),
            vec![CandidateAttributeValue::array(vec![
                CandidateAttributeValue::signed_integer(7),
                CandidateAttributeValue::string("nested".to_owned()),
            ])],
        )
        .validate(profile)?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "map".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "nested".to_owned(),
                    CandidateAttributeValue::boolean(false),
                ),
            ])],
        )
        .validate(profile)?,
    ];
    let observation = SpanObservation::checked_native(
        [0x61; 16],
        [0x62; 8],
        None,
        "typed".to_owned(),
        positron_domain::time::EventTime::missing(),
        positron_domain::time::EventTime::received(
            UnixNanoseconds::new(0),
            positron_domain::time::SourceTimeQuality::Zero,
        )?,
        attributes,
        SpanKind::Server,
        SamplingDecision::NotSampled,
        positron_policy::PolicyProvenance::new(2, [0x71; 32], vec!["rule".to_owned()])?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x69; 16])?,
                vec![observation.clone()],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let actual = result
        .observations()
        .first()
        .ok_or("missing typed span")?
        .observation();
    assert_eq!(actual, &observation);
    assert_eq!(
        actual.start_time(),
        positron_domain::time::EventTime::missing()
    );
    assert_eq!(
        actual.end_time().quality(),
        positron_domain::time::SourceTimeQuality::Zero
    );
    assert_eq!(
        actual
            .attributes()
            .first()
            .ok_or("missing resource attribute")?
            .occurrence(0)
            .ok_or("missing resource occurrence")?
            .as_signed_integer(),
        Some(200)
    );
    Ok(())
}

#[test]
fn malformed_trace_block_fails_closed_without_a_partial_result() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(9)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let store = TraceStore::new();
    let observation = SpanObservation::checked_minimal(
        [0x71; 16],
        [0x72; 8],
        None,
        "valid-prefix".to_owned(),
        None,
        None,
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let stored = StoredSpanObservation::new(observation, clock.assign_ingest_time()?);
    let mut malformed = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    malformed.push(0xff);
    ledger.append(positron_kernel::PreparedStoreBlock::new(
        scope,
        positron_kernel::StoreBlockIdentity::new([0x73; 16])?,
        malformed,
    )?)?;
    let failure = store
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("malformed native block must not yield a partial observation");
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    Ok(())
}

#[test]
fn malformed_trace_record_shapes_fail_closed_at_their_boundaries() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x20; 16])?,
        CatalogSecret::from_owned(Box::new([0x30; 32]), Box::new([0x40; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let profile = ValueLimitProfile::release_1_system_maximum();
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "key".to_owned(),
            vec![CandidateAttributeValue::boolean(true)],
        )
        .validate(profile)?,
    ];
    let observation = SpanObservation::checked_native(
        [0x71; 16],
        [0x72; 8],
        None,
        "valid".to_owned(),
        positron_domain::time::EventTime::missing(),
        positron_domain::time::EventTime::missing(),
        attributes,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [1; 32], Vec::new())?,
    )?;
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)))
            .assign_ingest_time()?,
    );
    let valid = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
    let wrong_tenant = codec::encode_block(
        TenantId::from_bytes([0x42; 16])?,
        std::slice::from_ref(&stored),
    )?;
    let mut trailing = valid.clone();
    trailing.push(0xff);
    let truncated = valid
        .get(..valid.len().saturating_sub(3))
        .ok_or("trace fixture was unexpectedly short")?
        .to_vec();
    let cases = vec![
        (
            "wrong magic",
            replaced_byte(&valid, 0, 0xff)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "wrong version",
            replaced_bytes(&valid, 8, [0, 2])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "wrong tenant",
            wrong_tenant,
            TraceStoreFailureCode::PhysicalScopeMismatch,
        ),
        (
            "zero records",
            replaced_bytes(&valid, 26, [0, 0])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "too many records",
            replaced_bytes(&valid, 26, [4, 1])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown parent marker",
            replaced_byte(&valid, 52, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown span kind",
            replaced_byte(&valid, 53, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown sampling decision",
            replaced_byte(&valid, 54, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown source time quality",
            replaced_byte(&valid, 55, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid span name",
            replaced_byte(&valid, 61, 0xff)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown attribute namespace",
            replaced_byte(&valid, 68, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "empty occurrence set",
            replaced_bytes(&valid, 76, [0, 0])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "unknown native value",
            replaced_byte(&valid, 78, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid native boolean",
            replaced_byte(&valid, 79, 9)?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "invalid policy provenance",
            replaced_bytes(&valid, 88, [0; 32])?,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "truncated block",
            truncated,
            TraceStoreFailureCode::MalformedBlock,
        ),
        (
            "trailing bytes",
            trailing,
            TraceStoreFailureCode::MalformedBlock,
        ),
    ];

    for (index, (description, bytes, expected)) in cases.into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(index + 20)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(index + 0x61)?; 32])),
        )?;
        ledger.append(positron_kernel::PreparedStoreBlock::new(
            scope,
            positron_kernel::StoreBlockIdentity::new([u8::try_from(index + 0x71)?; 16])?,
            bytes,
        )?)?;
        let failure = TraceStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
            )
            .expect_err(description);
        assert_eq!(failure.code(), expected, "{description}");
    }
    Ok(())
}

fn replaced_byte(bytes: &[u8], offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    *replaced
        .get_mut(offset)
        .ok_or("malformed fixture replacement offset")? = value;
    Ok(replaced)
}

fn replaced_bytes<const N: usize>(
    bytes: &[u8],
    offset: usize,
    values: [u8; N],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    replaced
        .get_mut(offset..offset + values.len())
        .ok_or("malformed fixture replacement range")?
        .copy_from_slice(&values);
    Ok(replaced)
}

fn preparation_capacity(
    authority: &StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<positron_kernel::ResourceReservation<'_>, Box<dyn Error>> {
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?;
    Ok(authority
        .governor()
        .reserve(WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)?)?)
}

fn establish_kernel_authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = positron_kernel::InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(add(add(durability, large)?, large)?, uniform(12))?;
    let ordinary_capacity = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary_capacity)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        positron_kernel::DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary_capacity)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, recovery)?,
    )?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| -> Result<u64, Box<dyn Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| "resource capacity overflow".into())
    };
    Ok(ResourceAmounts::new([
        value(ResourceDimension::MemoryBytes)?,
        value(ResourceDimension::QueueSlots)?,
        value(ResourceDimension::TaskSlots)?,
        value(ResourceDimension::BufferCacheBytes)?,
        value(ResourceDimension::BatchItems)?,
        value(ResourceDimension::LeaseSlots)?,
        value(ResourceDimension::RetrySlots)?,
        value(ResourceDimension::IoPermits)?,
        value(ResourceDimension::CpuWorkUnits)?,
        value(ResourceDimension::FileDescriptors)?,
        value(ResourceDimension::DiskHeadroomBytes)?,
    ]))
}

struct AlwaysCancelled;

impl ScanCancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct NeverObserved;

impl ScanObserver for NeverObserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

struct WorkBudgetExhausted;

impl ScanObserver for WorkBudgetExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}

struct BytesBudgetExhausted;

impl ScanObserver for BytesBudgetExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}

struct RecordsBudgetExhausted;

impl ScanObserver for RecordsBudgetExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_decoded_records(&self, _records: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}
