use super::super::*;
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct WorkMeter(Cell<u64>);

impl WorkMeter {
    const fn new() -> Self {
        Self(Cell::new(0))
    }

    fn work(&self) -> u64 {
        self.0.get()
    }
}

impl ScanObserver for WorkMeter {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let next = self
            .work()
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        self.0.set(next);
        Ok(())
    }
}

struct ExactWork(Cell<u64>);

impl ExactWork {
    const fn new(remaining: u64) -> Self {
        Self(Cell::new(remaining))
    }
}

impl ScanObserver for ExactWork {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let remaining = self
            .0
            .get()
            .checked_sub(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        self.0.set(remaining);
        Ok(())
    }
}

struct CancelAtWork {
    remaining: Cell<u64>,
    cancelled: Arc<AtomicBool>,
}

impl ScanObserver for CancelAtWork {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let remaining = self
            .remaining
            .get()
            .checked_sub(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        self.remaining.set(remaining);
        if remaining == 0 {
            self.cancelled.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

struct SharedCancellation(Arc<AtomicBool>);

impl ScanCancellation for SharedCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
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
    let observation = SpanObservation::checked_native(
        [0x11; 16],
        [0x22; 8],
        None,
        "checkout".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable).unwrap(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x76; 32], Vec::new()).unwrap(),
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
    let result = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.observations().len(), 1);
    assert!(result.complete());
    assert_eq!(
        result.incompleteness(),
        super::super::TraceIncompleteness::None
    );
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
    let observed_result = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &NeverObserved,
    )?;
    assert_eq!(observed_result.observations().len(), 1);
    assert!(observed_result.complete());
    drop(ledger);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x53; 32])),
    )?;
    let restarted = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert!(restarted.complete());
    assert_eq!(restarted.observations()[0].observation(), &observation);

    let limited = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(0),
    )?;
    assert!(limited.observations().is_empty());
    assert!(!limited.complete());
    assert_eq!(
        limited.incompleteness(),
        super::super::TraceIncompleteness::ScannedBytesLimit
    );
    drop(limited);

    let bounded_snapshot = ledger.snapshot()?;
    let block_bytes = u64::try_from(
        bounded_snapshot
            .blocks()
            .first()
            .ok_or("missing committed trace block")?
            .payload()
            .len(),
    )?;
    let exact_bytes = store.scan_physical(
        authority.governor(),
        tenant,
        &bounded_snapshot,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(block_bytes),
    )?;
    assert!(exact_bytes.complete());
    assert_eq!(exact_bytes.scanned_bytes(), block_bytes);
    let one_over_bytes = store.scan_physical(
        authority.governor(),
        tenant,
        &bounded_snapshot,
        TraceScan::all(ScanLimit::new(1)?).with_scanned_bytes(block_bytes + 1),
    )?;
    assert!(one_over_bytes.complete());
    assert_eq!(one_over_bytes.scanned_bytes(), block_bytes);

    let after_result = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after(ScanLimit::new(1)?, marker),
    )?;
    assert!(after_result.observations().is_empty());
    assert!(after_result.complete());
    let through_result = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::through(ScanLimit::new(1)?, marker),
    )?;
    assert_eq!(through_result.observations().len(), 1);
    let between_result = store.scan_physical(
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

    let before_cancel = authority.governor().inspect()?.outstanding_total();
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
    assert_eq!(after_cancel.outstanding_total(), before_cancel);

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
fn trace_by_id_returns_the_committed_active_trace_from_its_snapshot() -> Result<(), Box<dyn Error>>
{
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
    let attribute = positron_domain::value::AttributeOccurrenceSetCandidate::new(
        positron_domain::value::AttributeNamespace::Record,
        "http.response.status_code".to_owned(),
        vec![positron_domain::value::CandidateAttributeValue::signed_integer(503)],
    )
    .validate(ValueLimitProfile::release_1_system_maximum())?;
    let expected = attribute
        .occurrence(0)
        .ok_or("filter attribute occurrence")?
        .try_clone()?;
    let observation = SpanObservation::checked_native(
        [0x12; 16],
        [0x23; 8],
        None,
        "checkout".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable)?,
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable)?,
        vec![attribute],
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    let conflict = SpanObservation::checked_native(
        [0x12; 16],
        [0x23; 8],
        None,
        "checkout-conflict".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable)?,
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable)?,
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new())?,
    )?;
    let second_span = SpanObservation::checked_native(
        [0x12; 16],
        [0x24; 8],
        None,
        "second".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new())?,
    )?;
    let target_first = SpanObservation::checked_native(
        [0x13; 16],
        [0x25; 8],
        None,
        "target-first".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new())?,
    )?;
    let target_second = SpanObservation::checked_native(
        [0x13; 16],
        [0x26; 8],
        None,
        "target-second".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new())?,
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x64; 16])?,
                vec![
                    observation,
                    conflict,
                    second_span,
                    target_first,
                    target_second,
                ],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;

    let trace = store.trace_by_id(
        authority.governor(),
        tenant,
        &snapshot,
        [0x12; 16],
        TraceSearch::all(ScanLimit::new(5)?),
    )?;

    assert_eq!(trace.trace_id(), [0x12; 16]);
    assert_eq!(trace.spans().len(), 2);
    assert_eq!(trace.spans()[0].span_id(), [0x23; 8]);
    assert_eq!(trace.spans()[0].variants().len(), 2);
    assert_eq!(trace.spans()[1].span_id(), [0x24; 8]);
    assert!(trace.complete());

    let search = store.search(
        authority.governor(),
        tenant,
        &snapshot,
        TraceSearch::all(ScanLimit::new(5)?),
    )?;
    assert_eq!(search.spans().len(), 4);
    assert_eq!(search.spans()[0].trace_id(), [0x12; 16]);
    assert_eq!(search.spans()[0].variants().len(), 2);
    assert!(search.complete());

    let target = store.trace_by_id(
        authority.governor(),
        tenant,
        &snapshot,
        [0x13; 16],
        TraceSearch::all(ScanLimit::new(5)?),
    )?;
    assert_eq!(
        target
            .spans()
            .iter()
            .map(|span| span.span_id())
            .collect::<Vec<_>>(),
        vec![[0x25; 8], [0x26; 8]]
    );

    let filtered = store.search(
        authority.governor(),
        tenant,
        &snapshot,
        TraceSearch::all(ScanLimit::new(2)?).with_attribute_equals(
            positron_domain::value::AttributeNamespace::Record,
            "http.response.status_code".to_owned(),
            expected,
        )?,
    )?;
    assert_eq!(filtered.spans().len(), 1);
    assert_eq!(filtered.spans()[0].trace_id(), [0x12; 16]);
    assert_eq!(filtered.spans()[0].variants().len(), 2);

    let non_matching = positron_domain::value::AttributeOccurrenceSetCandidate::new(
        positron_domain::value::AttributeNamespace::Record,
        "http.response.status_code".to_owned(),
        vec![positron_domain::value::CandidateAttributeValue::signed_integer(504)],
    )
    .validate(ValueLimitProfile::release_1_system_maximum())?
    .occurrence(0)
    .ok_or("missing non-matching occurrence")?
    .try_clone()?;
    let absent = store.trace_by_id(
        authority.governor(),
        tenant,
        &snapshot,
        [0x12; 16],
        TraceSearch::all(ScanLimit::new(2)?).with_attribute_equals(
            positron_domain::value::AttributeNamespace::Record,
            "http.response.status_code".to_owned(),
            non_matching,
        )?,
    )?;
    assert!(absent.spans().is_empty());

    let scan_work = WorkMeter::new();
    let scanned = store.scan_observed(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(2)?),
        &NeverCancelled,
        &scan_work,
    )?;
    drop(scanned);
    let selection_start = scan_work.work();
    let search_work = WorkMeter::new();
    let searched = store.search_observed(
        authority.governor(),
        tenant,
        &snapshot,
        TraceSearch::all(ScanLimit::new(2)?),
        &NeverCancelled,
        &search_work,
    )?;
    drop(searched);
    assert!(search_work.work() > selection_start);

    let cumulative = ExactWork::new(search_work.work());
    let first_cumulative = store.search_observed(
        authority.governor(),
        tenant,
        &snapshot,
        TraceSearch::all(ScanLimit::new(2)?),
        &NeverCancelled,
        &cumulative,
    )?;
    drop(first_cumulative);
    let cumulative_failure = store
        .search_observed(
            authority.governor(),
            tenant,
            &snapshot,
            TraceSearch::all(ScanLimit::new(2)?),
            &NeverCancelled,
            &cumulative,
        )
        .expect_err("one shared observer must bound cumulative searches");
    assert_eq!(
        cumulative_failure.code(),
        TraceStoreFailureCode::BudgetExhausted
    );

    let bounded_selection = ExactWork::new(selection_start);
    let selection_failure = store
        .search_observed(
            authority.governor(),
            tenant,
            &snapshot,
            TraceSearch::all(ScanLimit::new(2)?),
            &NeverCancelled,
            &bounded_selection,
        )
        .expect_err("selection must charge work after physical scan and consolidation");
    assert_eq!(
        selection_failure.code(),
        TraceStoreFailureCode::BudgetExhausted
    );

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancellation = SharedCancellation(Arc::clone(&cancelled));
    let cancel_after_consolidation = CancelAtWork {
        remaining: Cell::new(selection_start),
        cancelled,
    };
    let cancellation_failure = store
        .search_observed(
            authority.governor(),
            tenant,
            &snapshot,
            TraceSearch::all(ScanLimit::new(2)?),
            &cancellation,
            &cancel_after_consolidation,
        )
        .expect_err("selection must poll cancellation after consolidation");
    assert_eq!(
        cancellation_failure.code(),
        TraceStoreFailureCode::Cancelled
    );
    Ok(())
}

#[test]
fn trace_by_id_applies_a_non_matching_native_attribute_predicate() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(31)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
    )?;
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "http.status_code".to_owned(),
            vec![CandidateAttributeValue::signed_integer(200)],
        )
        .validate(ValueLimitProfile::release_1_system_maximum())?,
    ];
    let observation = SpanObservation::checked_native(
        [0x35; 16],
        [0x36; 8],
        None,
        "predicate".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        attributes,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x37; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x38; 16])?,
                vec![observation],
            )?
            .into_store_block(),
    )?;
    let expected = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "http.status_code".to_owned(),
        vec![CandidateAttributeValue::signed_integer(404)],
    )
    .validate(ValueLimitProfile::release_1_system_maximum())?
    .occurrence(0)
    .ok_or("missing predicate occurrence")?
    .try_clone()?;

    let result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        [0x35; 16],
        TraceSearch::all(ScanLimit::new(1)?).with_attribute_equals(
            AttributeNamespace::Record,
            "http.status_code".to_owned(),
            expected,
        )?,
    )?;
    assert!(result.complete());
    assert!(result.spans().is_empty());
    Ok(())
}

#[test]
fn native_predicate_preserves_later_matching_span_order() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x51; 16])?,
        CatalogSecret::from_owned(Box::new([0x52; 32]), Box::new([0x53; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(51)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    let matching = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "http.status_code".to_owned(),
        vec![CandidateAttributeValue::signed_integer(200)],
    )
    .validate(ValueLimitProfile::release_1_system_maximum())?;
    let predicate = matching
        .occurrence(0)
        .ok_or("missing matching predicate occurrence")?
        .try_clone()?;
    let observed_predicate = predicate.try_clone()?;
    let observation = |trace_id, span_id, attributes, name| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            None,
            name,
            EventTime::missing(),
            EventTime::missing(),
            attributes,
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x55; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x56; 16])?,
                vec![
                    observation(
                        [0x43; 16],
                        [0x26; 8],
                        vec![matching.clone()],
                        "later".to_owned(),
                    )?,
                    observation([0x42; 16], [0x24; 8], Vec::new(), "non-matching".to_owned())?,
                    observation([0x43; 16], [0x25; 8], vec![matching], "first".to_owned())?,
                ],
            )?
            .into_store_block(),
    )?;

    let result = store.search(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceSearch::all(ScanLimit::new(3)?).with_attribute_equals(
            AttributeNamespace::Record,
            "http.status_code".to_owned(),
            predicate.try_clone()?,
        )?,
    )?;

    assert!(result.complete());
    assert_eq!(
        result
            .spans()
            .iter()
            .map(|span| (span.trace_id(), span.span_id()))
            .collect::<Vec<_>>(),
        vec![([0x43; 16], [0x25; 8]), ([0x43; 16], [0x26; 8])]
    );

    let successful_work = WorkMeter::new();
    let observed = store.search_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceSearch::all(ScanLimit::new(3)?).with_attribute_equals(
            AttributeNamespace::Record,
            "http.status_code".to_owned(),
            observed_predicate,
        )?,
        &NeverCancelled,
        &successful_work,
    )?;
    assert_eq!(
        observed
            .spans()
            .iter()
            .map(|span| (span.trace_id(), span.span_id()))
            .collect::<Vec<_>>(),
        vec![([0x43; 16], [0x25; 8]), ([0x43; 16], [0x26; 8])]
    );
    let total_work = successful_work.work();
    assert!(total_work > 0);

    let rejected_budget = ExactWork::new(
        total_work
            .checked_sub(1)
            .ok_or("successful observed search recorded no work")?,
    );
    let budget_failure = store
        .search_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceSearch::all(ScanLimit::new(3)?).with_attribute_equals(
                AttributeNamespace::Record,
                "http.status_code".to_owned(),
                predicate.try_clone()?,
            )?,
            &NeverCancelled,
            &rejected_budget,
        )
        .expect_err("rejected-prefix compaction must stay inside the caller work budget");
    assert_eq!(
        budget_failure.code(),
        TraceStoreFailureCode::BudgetExhausted
    );

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancellation = SharedCancellation(Arc::clone(&cancelled));
    let final_charge_cancellation = CancelAtWork {
        remaining: Cell::new(total_work),
        cancelled,
    };
    let cancellation_failure = store
        .search_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceSearch::all(ScanLimit::new(3)?).with_attribute_equals(
                AttributeNamespace::Record,
                "http.status_code".to_owned(),
                predicate,
            )?,
            &cancellation,
            &final_charge_cancellation,
        )
        .expect_err("cancellation after the final accepted work charge must stop compaction");
    assert_eq!(
        cancellation_failure.code(),
        TraceStoreFailureCode::Cancelled
    );
    Ok(())
}
