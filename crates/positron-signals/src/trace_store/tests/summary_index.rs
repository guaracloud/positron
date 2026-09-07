use super::*;
use crate::{TraceQuietPeriod, TraceSummaryMaintainer};
use std::cell::Cell;

const DISTINCT_TRACE_BATCH: u16 = 512;
const SUMMARY_WORK_PER_TRACE: u64 = 64;
const QUIESCENCE_FRONTIER_TRACES: u8 = 80;

struct WorkMeter(Cell<u64>);

impl WorkMeter {
    const fn new() -> Self {
        Self(Cell::new(0))
    }

    fn work(&self) -> u64 {
        self.0.get()
    }
}

struct WorkBudget(Cell<u64>);

impl WorkBudget {
    const fn exact(work: u64) -> Self {
        Self(Cell::new(work))
    }
}

impl ScanObserver for WorkMeter {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        self.0.set(self.0.get().saturating_add(units));
        Ok(())
    }
}

impl ScanObserver for WorkBudget {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let Some(remaining) = self.0.get().checked_sub(units) else {
            return Err(ScanObservationFailureCode::BudgetExhausted);
        };
        self.0.set(remaining);
        Ok(())
    }
}

#[test]
fn summary_maintenance_keeps_a_many_trace_frontier_within_a_linear_work_budget()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xf1; 16])?,
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(61)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf4; 32])),
    )?;
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(usize::from(DISTINCT_TRACE_BATCH))
        .map_err(|_| "test observation allocation failed")?;
    for trace_value in 1..=DISTINCT_TRACE_BATCH {
        observations.push(SpanObservation::checked_native(
            full_width_trace_id(trace_value),
            [0xf5; 8],
            None,
            "many-trace".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xf6; 32], Vec::new())?,
        )?);
    }
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0xf7; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let physical_work = WorkMeter::new();
    let physical = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(usize::from(DISTINCT_TRACE_BATCH))?),
        &NeverCancelled,
        &physical_work,
    )?;
    assert_eq!(
        physical.observations().len(),
        usize::from(DISTINCT_TRACE_BATCH)
    );
    drop(physical);
    let allowance = physical_work
        .work()
        .checked_add(
            u64::from(DISTINCT_TRACE_BATCH)
                .checked_mul(SUMMARY_WORK_PER_TRACE)
                .ok_or("summary work allowance overflow")?,
        )
        .ok_or("summary work allowance overflow")?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(usize::from(DISTINCT_TRACE_BATCH))?,
    )?;
    let maintained = maintainer.maintain(
        &store,
        &snapshot,
        &NeverCancelled,
        &WorkBudget::exact(allowance),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    )?;
    assert!(maintained.complete());
    assert_eq!(
        maintained.applied_observations(),
        u64::from(DISTINCT_TRACE_BATCH)
    );
    assert_eq!(
        maintained
            .summary(full_width_trace_id(1))
            .ok_or("first distinct trace was not summarized")?
            .observation_count(),
        1
    );
    assert_eq!(
        maintained
            .summary(full_width_trace_id(DISTINCT_TRACE_BATCH))
            .ok_or("last distinct trace was not summarized")?
            .observation_count(),
        1
    );
    Ok(())
}

fn full_width_trace_id(value: u16) -> [u8; 16] {
    let value = u64::from(value);
    let first = value.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
    let second = value.wrapping_mul(0xbf58_476d_1ce4_e5b9).rotate_left(41) ^ 0x94d0_49bb_1331_11eb;
    let mut trace_id = [0_u8; 16];
    trace_id[..8].copy_from_slice(&first.to_be_bytes());
    trace_id[8..].copy_from_slice(&second.to_be_bytes());
    trace_id
}

#[test]
fn summary_maintenance_bounds_quiescence_after_one_delta_on_a_large_frontier()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xf8; 16])?,
        CatalogSecret::from_owned(Box::new([0xf9; 32]), Box::new([0xfa; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(62)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xfb; 32])),
    )?;
    let store = TraceStore::new();
    let mut observations = Vec::new();
    for trace_value in 1..=QUIESCENCE_FRONTIER_TRACES {
        observations.push(SpanObservation::checked_native(
            [trace_value; 16],
            [0xfc; 8],
            None,
            "quiescence-frontier".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xfd; 32], Vec::new())?,
        )?);
    }
    let initial = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0xfe; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    for _ in 0..QUIESCENCE_FRONTIER_TRACES {
        let maintained = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(maintained.applied_observations(), 1);
    }
    let delta = SpanObservation::checked_native(
        [1; 16],
        [0xff; 8],
        None,
        "late-quiescence-delta".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xf0; 32], Vec::new())?,
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                StoreBlockIdentity::new([0xf1; 16])?,
                vec![delta],
            )?
            .into_store_block(),
    )?;
    let physical_work = WorkMeter::new();
    let physical = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after_cursor(
            ScanLimit::new(1)?,
            initial.position(),
            positron_domain::routing::RecordOrdinal::new(u16::from(
                QUIESCENCE_FRONTIER_TRACES - 1,
            ))?,
        ),
        &NeverCancelled,
        &physical_work,
    )?;
    assert!(physical.complete());
    drop(physical);
    let allowance = physical_work
        .work()
        .checked_add(SUMMARY_WORK_PER_TRACE)
        .ok_or("bounded quiescence allowance overflow")?;
    let maintained = maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &WorkBudget::exact(allowance),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
    )?;
    assert_eq!(maintained.applied_observations(), 1);
    assert!(maintained.complete());
    assert!(
        !maintained.quiescence_complete(),
        "one bounded refresh must not claim that every retained trace is current"
    );
    assert_eq!(
        maintained
            .summary([1; 16])
            .ok_or("late trace summary is present")?
            .observation_count(),
        2
    );
    Ok(())
}

#[test]
fn summary_maintenance_resumes_quiescence_after_budget_exhaustion() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(63)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    let policy = positron_policy::PolicyProvenance::new(1, [0xe5; 32], Vec::new())?;
    let observations = [[1; 16], [2; 16], [3; 16]].map(|trace_id| {
        SpanObservation::checked_native(
            trace_id,
            [0xe6; 8],
            None,
            "quiescence-retry".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            policy.clone(),
        )
    });
    let observations = observations.into_iter().collect::<Result<Vec<_>, _>>()?;
    let store = TraceStore::new();
    let receipt = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0xe7; 16])?,
                observations,
            )?
            .into_store_block(),
    )?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(3)?,
    )?;
    maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    )?;

    let scan_work = WorkMeter::new();
    let scan = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after_cursor(
            ScanLimit::new(3)?,
            receipt.position(),
            positron_domain::routing::RecordOrdinal::new(2)?,
        ),
        &NeverCancelled,
        &scan_work,
    )?;
    assert!(scan.observations().is_empty());
    drop(scan);
    let allowance = scan_work
        .work()
        .checked_add(1)
        .ok_or("quiescence retry allowance overflow")?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105)));
    for _ in 0..2 {
        let failure = match maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &WorkBudget::exact(allowance),
            &clock,
        ) {
            Ok(_) => return Err("one bounded retry must exhaust its work budget".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), TraceStoreFailureCode::BudgetExhausted);
    }
    let completed = maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &WorkBudget::exact(allowance),
        &clock,
    )?;
    assert!(completed.complete());
    assert!(completed.quiescence_complete());
    for trace_id in [[1; 16], [2; 16], [3; 16]] {
        assert!(
            completed
                .summary(trace_id)
                .ok_or("retained trace summary is present")?
                .quiescent()
        );
    }
    Ok(())
}
