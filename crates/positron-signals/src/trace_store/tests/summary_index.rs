use super::*;
use crate::{TraceQuietPeriod, TraceSummaryMaintainer};
use std::cell::Cell;

const DISTINCT_TRACE_BATCH: u16 = 512;
const SUMMARY_WORK_PER_TRACE: u64 = 64;

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
        let mut trace_id = [0_u8; 16];
        trace_id[..2].copy_from_slice(&trace_value.to_be_bytes());
        observations.push(SpanObservation::checked_native(
            trace_id,
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
            .summary({
                let mut trace_id = [0_u8; 16];
                trace_id[1] = 1;
                trace_id
            })
            .ok_or("first distinct trace was not summarized")?
            .observation_count(),
        1
    );
    assert_eq!(
        maintained
            .summary({
                let mut trace_id = [0_u8; 16];
                trace_id[..2].copy_from_slice(&DISTINCT_TRACE_BATCH.to_be_bytes());
                trace_id
            })
            .ok_or("last distinct trace was not summarized")?
            .observation_count(),
        1
    );
    Ok(())
}
