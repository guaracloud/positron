use super::super::*;
use crate::TraceStoreFailure;
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct ExhaustAfterWork(Cell<u64>);

impl ExhaustAfterWork {
    const fn new(remaining: u64) -> Self {
        Self(Cell::new(remaining))
    }
}

impl ScanObserver for ExhaustAfterWork {
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

struct CancelAfterWork {
    remaining: Cell<u64>,
    cancelled: Arc<AtomicBool>,
}

impl ScanObserver for CancelAfterWork {
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
fn trace_by_id_analysis_reports_structure_and_a_critical_path() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(71)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    let trace_id = [0x75; 16];
    let observation = |trace_id, span_id, parent_span_id, start, end, name| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            parent_span_id,
            name,
            EventTime::received(UnixNanoseconds::new(start), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(end), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0x76; 32], Vec::new())?,
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
                StoreBlockIdentity::new([0x77; 16])?,
                vec![
                    observation(trace_id, [0x11; 8], None, 1, 33, "root".to_owned())?,
                    observation(
                        trace_id,
                        [0x12; 8],
                        Some([0x11; 8]),
                        2,
                        22,
                        "first".to_owned(),
                    )?,
                    observation(
                        trace_id,
                        [0x13; 8],
                        Some([0x11; 8]),
                        3,
                        32,
                        "second".to_owned(),
                    )?,
                ],
            )?
            .into_store_block(),
    )?;

    let mut trace = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        trace_id,
        TraceSearch::all(ScanLimit::new(3)?),
    )?;
    let structure = trace.analyze_structure(&NeverCancelled, &NeverObserved)?;

    assert!(structure.complete());
    assert_eq!(structure.roots(), &[[0x11; 8]]);
    assert!(structure.orphans().is_empty());
    assert!(structure.cycles().is_empty());
    assert_eq!(structure.spans().len(), 3);
    let critical_path = structure.critical_path().ok_or("critical path")?;
    assert_eq!(
        critical_path
            .fragments()
            .iter()
            .map(|fragment| fragment.span_id())
            .collect::<Vec<_>>(),
        vec![[0x11; 8], [0x13; 8], [0x11; 8]]
    );
    assert_eq!(critical_path.duration_nanos(), 32);

    let serial_trace = [0x78; 16];
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x79; 16])?,
                vec![
                    observation(serial_trace, [0x21; 8], None, 1, 30, "root".to_owned())?,
                    observation(
                        serial_trace,
                        [0x22; 8],
                        Some([0x21; 8]),
                        2,
                        12,
                        "first".to_owned(),
                    )?,
                    observation(
                        serial_trace,
                        [0x23; 8],
                        Some([0x21; 8]),
                        14,
                        24,
                        "second".to_owned(),
                    )?,
                ],
            )?
            .into_store_block(),
    )?;
    let mut serial = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        serial_trace,
        TraceSearch::all(ScanLimit::new(6)?),
    )?;
    let serial_structure = serial.analyze_structure(&NeverCancelled, &NeverObserved)?;
    let serial_path = serial_structure
        .critical_path()
        .ok_or("serial critical path")?;
    assert_eq!(
        serial_path
            .fragments()
            .iter()
            .map(|fragment| fragment.span_id())
            .collect::<Vec<_>>(),
        vec![[0x21; 8], [0x22; 8], [0x21; 8], [0x23; 8], [0x21; 8]]
    );
    assert_eq!(serial_path.duration_nanos(), 29);

    let boundary_trace = [0x7a; 16];
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(102))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x7b; 16])?,
                vec![
                    observation(boundary_trace, [0x31; 8], None, 1, 10, "root".to_owned())?,
                    observation(
                        boundary_trace,
                        [0x32; 8],
                        Some([0x31; 8]),
                        2,
                        10,
                        "child".to_owned(),
                    )?,
                ],
            )?
            .into_store_block(),
    )?;
    let mut boundary = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        boundary_trace,
        TraceSearch::all(ScanLimit::new(8)?),
    )?;
    let boundary_structure = boundary.analyze_structure(&NeverCancelled, &NeverObserved)?;
    let boundary_path = boundary_structure
        .critical_path()
        .ok_or("boundary critical path")?;
    assert_eq!(
        boundary_path
            .fragments()
            .iter()
            .map(|fragment| fragment.span_id())
            .collect::<Vec<_>>(),
        vec![[0x31; 8], [0x32; 8]]
    );
    assert_eq!(boundary_path.duration_nanos(), 9);

    let orphan_trace = [0x7c; 16];
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(103))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x7d; 16])?,
                vec![observation(
                    orphan_trace,
                    [0x41; 8],
                    Some([0x42; 8]),
                    2,
                    9,
                    "orphan".to_owned(),
                )?],
            )?
            .into_store_block(),
    )?;
    let mut orphan = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        orphan_trace,
        TraceSearch::all(ScanLimit::new(9)?),
    )?;
    let orphan_structure = orphan.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(!orphan_structure.complete());
    assert_eq!(orphan_structure.orphans(), &[[0x41; 8]]);
    assert_eq!(orphan_structure.incompleteness().missing_parents(), 1);
    assert!(orphan_structure.critical_path().is_none());

    let mut cancelled = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        boundary_trace,
        TraceSearch::all(ScanLimit::new(9)?),
    )?;
    let cancellation = cancelled
        .analyze_structure(&AlwaysCancelled, &NeverObserved)
        .expect_err("analysis must honor caller cancellation");
    assert_eq!(cancellation.code(), TraceStoreFailureCode::Cancelled);

    let mut budget_limited = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        boundary_trace,
        TraceSearch::all(ScanLimit::new(9)?),
    )?;
    let budget = budget_limited
        .analyze_structure(&NeverCancelled, &WorkBudgetExhausted)
        .expect_err("analysis must honor caller work budget");
    assert_eq!(budget.code(), TraceStoreFailureCode::BudgetExhausted);

    let mut traversal_budget_limited = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        trace_id,
        TraceSearch::all(ScanLimit::new(9)?),
    )?;
    let traversal_budget = traversal_budget_limited
        .analyze_structure(&NeverCancelled, &ExhaustAfterWork::new(4))
        .expect_err("analysis must apply its work budget after initial entry");
    assert_eq!(
        traversal_budget.code(),
        TraceStoreFailureCode::BudgetExhausted
    );

    let cancellation_state = Arc::new(AtomicBool::new(false));
    let mut traversal_cancelled = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        trace_id,
        TraceSearch::all(ScanLimit::new(9)?),
    )?;
    let traversal_cancellation = traversal_cancelled
        .analyze_structure(
            &SharedCancellation(Arc::clone(&cancellation_state)),
            &CancelAfterWork {
                remaining: Cell::new(4),
                cancelled: Arc::clone(&cancellation_state),
            },
        )
        .expect_err("analysis must poll cancellation during graph traversal");
    assert_eq!(
        traversal_cancellation.code(),
        TraceStoreFailureCode::Cancelled
    );

    let mut scan_limited = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        trace_id,
        TraceSearch::all(ScanLimit::new(1)?),
    )?;
    let limited_structure = scan_limited.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(!limited_structure.complete());
    assert_eq!(
        limited_structure.incompleteness().scan(),
        TraceIncompleteness::ResultLimit
    );
    assert!(limited_structure.critical_path().is_none());
    Ok(())
}

#[test]
fn trace_by_id_analysis_surfaces_cycles_conflicts_and_source_time_failures()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(81)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x84; 32])),
    )?;
    let observation = |trace_id, span_id, parent_span_id, start, end, name| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            parent_span_id,
            name,
            EventTime::received(UnixNanoseconds::new(start), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(end), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0x85; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    let append = |identity, clock, observations| -> Result<(), Box<dyn Error>> {
        ledger.append(
            store
                .prepare_unretained_for_test(
                    preparation_capacity(&authority, tenant)?,
                    &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                        clock,
                    ))),
                    tenant,
                    shard,
                    StoreBlockIdentity::new([identity; 16])?,
                    observations,
                )?
                .into_store_block(),
        )?;
        Ok(())
    };

    let cycle = [0x86; 16];
    append(
        0x87,
        100,
        vec![
            observation(cycle, [0x01; 8], Some([0x02; 8]), 1, 10, "first".to_owned())?,
            observation(cycle, [0x02; 8], Some([0x01; 8]), 2, 9, "second".to_owned())?,
        ],
    )?;
    let mut cycle_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        cycle,
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    let cycle_structure = cycle_result.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(!cycle_structure.complete());
    assert!(cycle_structure.roots().is_empty());
    assert_eq!(cycle_structure.cycles(), &[[0x01; 8], [0x02; 8]]);
    assert_eq!(cycle_structure.incompleteness().cycle_members(), 2);
    assert!(cycle_structure.critical_path().is_none());

    let conflict = [0x88; 16];
    append(
        0x89,
        101,
        vec![
            observation(conflict, [0x11; 8], None, 1, 10, "first".to_owned())?,
            observation(conflict, [0x11; 8], None, 1, 10, "conflict".to_owned())?,
        ],
    )?;
    let mut conflict_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        conflict,
        TraceSearch::all(ScanLimit::new(4)?),
    )?;
    let conflict_structure = conflict_result.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(!conflict_structure.complete());
    assert_eq!(conflict_structure.incompleteness().conflicts(), 1);
    assert!(conflict_structure.spans()[0].conflicted());
    assert!(conflict_structure.critical_path().is_none());

    let invalid = [0x8a; 16];
    append(
        0x8b,
        102,
        vec![observation(
            invalid,
            [0x21; 8],
            None,
            10,
            1,
            "negative duration".to_owned(),
        )?],
    )?;
    let mut invalid_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        invalid,
        TraceSearch::all(ScanLimit::new(5)?),
    )?;
    let invalid_structure = invalid_result.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(!invalid_structure.complete());
    assert_eq!(invalid_structure.incompleteness().invalid_durations(), 1);
    assert!(invalid_structure.critical_path().is_none());

    let escaped = [0x8c; 16];
    append(
        0x8d,
        103,
        vec![
            observation(escaped, [0x31; 8], None, 1, 10, "root".to_owned())?,
            observation(
                escaped,
                [0x32; 8],
                Some([0x31; 8]),
                2,
                12,
                "escaped child".to_owned(),
            )?,
        ],
    )?;
    let mut escaped_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        escaped,
        TraceSearch::all(ScanLimit::new(7)?),
    )?;
    let escaped_structure = escaped_result.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(!escaped_structure.complete());
    assert_eq!(
        escaped_structure
            .incompleteness()
            .temporal_inconsistencies(),
        1
    );
    assert!(escaped_structure.critical_path().is_none());

    let long_cycle = [0x8e; 16];
    let mut long_cycle_observations = Vec::new();
    for value in 1_u8..=64 {
        long_cycle_observations.push(observation(
            long_cycle,
            [value; 8],
            Some([if value == 64 { 1 } else { value + 1 }; 8]),
            1,
            100,
            format!("cycle-{value}"),
        )?);
    }
    append(0x8f, 104, long_cycle_observations)?;
    let mut long_cycle_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        long_cycle,
        TraceSearch::all(ScanLimit::new(1_024)?),
    )?;
    let long_cycle_structure =
        long_cycle_result.analyze_structure(&NeverCancelled, &ExhaustAfterWork::new(10_000))?;
    assert!(!long_cycle_structure.complete());
    assert!(long_cycle_structure.roots().is_empty());
    assert_eq!(long_cycle_structure.cycles().len(), 64);
    assert_eq!(long_cycle_structure.incompleteness().cycle_members(), 64);
    assert!(long_cycle_structure.critical_path().is_none());
    Ok(())
}

#[test]
fn trace_by_id_analysis_bounds_complete_deep_critical_path_work() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(91)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
    )?;
    let trace_id = [0x95; 16];
    let mut observations = Vec::new();
    for value in 1_u8..=64 {
        observations.push(SpanObservation::checked_native(
            trace_id,
            [value; 8],
            (value > 1).then_some([value - 1; 8]),
            format!("deep-{value}"),
            EventTime::received(
                UnixNanoseconds::new(i64::from(value)),
                SourceTimeQuality::Usable,
            )
            .map_err(TraceStoreFailure::domain)?,
            EventTime::received(
                UnixNanoseconds::new(131 - i64::from(value)),
                SourceTimeQuality::Usable,
            )
            .map_err(TraceStoreFailure::domain)?,
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0x96; 32], Vec::new())?,
        )?);
    }
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(200))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x97; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    let mut trace = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        trace_id,
        TraceSearch::all(ScanLimit::new(64)?),
    )?;
    let structure = trace.analyze_structure(&NeverCancelled, &ExhaustAfterWork::new(2_000))?;
    assert!(structure.complete());
    let critical_path = structure.critical_path().ok_or("deep critical path")?;
    assert_eq!(critical_path.duration_nanos(), 129);
    assert_eq!(critical_path.fragments().len(), 127);
    assert_eq!(
        critical_path
            .fragments()
            .first()
            .map(|fragment| fragment.span_id()),
        Some([1; 8])
    );
    assert_eq!(
        critical_path
            .fragments()
            .last()
            .map(|fragment| fragment.span_id()),
        Some([1; 8])
    );
    Ok(())
}
