use super::*;
use crate::{
    SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails, SpanObservationDetailsInput,
    SpanResourceMetadata, SpanScopeMetadata, SpanStatus, SpanStatusCode, TraceQuietPeriod,
    TraceSummaryMaintainer, TraceSummaryTimeProvenance,
};
use std::cell::{Cell, RefCell};
use std::sync::Mutex;

struct SequenceLifecycleClock(Mutex<Vec<UnixNanoseconds>>);

impl positron_kernel::LifecycleClockSource for SequenceLifecycleClock {
    fn read(&self) -> Result<UnixNanoseconds, positron_kernel::LifecycleClockFailure> {
        self.0
            .lock()
            .map_err(|_| positron_kernel::LifecycleClockFailure::Unavailable)?
            .pop()
            .ok_or(positron_kernel::LifecycleClockFailure::Unavailable)
    }
}

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

struct MaintenanceAdmissionObserver<'authority> {
    governor: positron_kernel::ResourceGovernor<'authority>,
    interactive_baseline: u32,
    maintenance_baseline: u32,
    observed_maintenance_claim: Cell<bool>,
    observed_interactive: Cell<u32>,
    observed_maintenance: Cell<u32>,
}

impl MaintenanceAdmissionObserver<'_> {
    fn observed_maintenance_claim(&self) -> bool {
        self.observed_maintenance_claim.get()
    }
}

impl ScanObserver for MaintenanceAdmissionObserver<'_> {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        let inspection = self
            .governor
            .inspect()
            .map_err(|_| ScanObservationFailureCode::BudgetExhausted)?;
        let interactive =
            inspection.outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail);
        let maintenance =
            inspection.outstanding_for(positron_kernel::WorkClass::OrdinaryMaintenanceBackup);
        self.observed_interactive.set(interactive);
        self.observed_maintenance.set(maintenance);
        self.observed_maintenance_claim.set(
            interactive == self.interactive_baseline && maintenance > self.maintenance_baseline,
        );
        Ok(())
    }
}

impl WorkBudget {
    const fn exact(work: u64) -> Self {
        Self(Cell::new(work))
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

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

impl ScanObserver for WorkMeter {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        self.0.set(self.0.get().saturating_add(units));
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

struct ResizeBlocker<'authority> {
    governor: positron_kernel::ResourceGovernor<'authority>,
    tenant: TenantId,
    arm_after_work: u64,
    observed_work: std::cell::Cell<u64>,
    blocker: RefCell<Option<positron_kernel::ResourceReservation<'authority>>>,
}

impl<'authority> ResizeBlocker<'authority> {
    fn new(
        governor: positron_kernel::ResourceGovernor<'authority>,
        tenant: TenantId,
        arm_after_work: u64,
    ) -> Self {
        Self {
            governor,
            tenant,
            arm_after_work,
            observed_work: std::cell::Cell::new(0),
            blocker: RefCell::new(None),
        }
    }

    fn armed(&self) -> bool {
        self.blocker.borrow().is_some()
    }

    fn release(&self) {
        drop(self.blocker.borrow_mut().take());
    }
}

impl ScanObserver for ResizeBlocker<'_> {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let observed = self.observed_work.get().saturating_add(units);
        self.observed_work.set(observed);
        if observed != self.arm_after_work || self.blocker.borrow().is_some() {
            return Ok(());
        }
        let snapshot = self
            .governor
            .inspect()
            .map_err(|_| ScanObservationFailureCode::BudgetExhausted)?;
        let dimension = ResourceDimension::MemoryBytes;
        let shared = snapshot
            .pool_capacity(positron_kernel::OrdinaryPool::Shared, dimension)
            .checked_sub(snapshot.pool_usage(positron_kernel::OrdinaryPool::Shared, dimension))
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        let maintenance = snapshot
            .pool_capacity(
                positron_kernel::OrdinaryPool::OrdinaryMaintenanceBackup,
                dimension,
            )
            .checked_sub(snapshot.pool_usage(
                positron_kernel::OrdinaryPool::OrdinaryMaintenanceBackup,
                dimension,
            ))
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        let amount = shared
            .checked_add(maintenance)
            .and_then(|available| available.checked_sub(1))
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        let claim = WorkClaim::tenant(
            self.tenant,
            WorkKind::OrdinaryMaintenanceBackup,
            ResourceAmounts::only(dimension, amount)
                .map_err(|_| ScanObservationFailureCode::BudgetExhausted)?,
        )
        .map_err(|_| ScanObservationFailureCode::BudgetExhausted)?;
        let blocker = self
            .governor
            .reserve(claim)
            .map_err(|_| ScanObservationFailureCode::BudgetExhausted)?;
        *self.blocker.borrow_mut() = Some(blocker);
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
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
    let observation = SpanObservation::checked_native(
        [0x31; 16],
        [0x32; 8],
        None,
        "retry".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable).unwrap(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x80; 32], Vec::new()).unwrap(),
    )?;
    let conflict = SpanObservation::checked_native(
        [0x31; 16],
        [0x32; 8],
        None,
        "conflicting-retry".to_owned(),
        EventTime::received(UnixNanoseconds::new(10), SourceTimeQuality::Usable).unwrap(),
        EventTime::received(UnixNanoseconds::new(20), SourceTimeQuality::Usable).unwrap(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0x81; 32], Vec::new()).unwrap(),
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
    let result = store.scan_physical(
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
    drop(result);
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    assert!(logical.complete());
    assert_eq!(logical.incompleteness(), TraceIncompleteness::None);
    assert_eq!(logical.decoded_observations(), 3);
    assert_eq!(logical.spans().len(), 1);
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(span.trace_id(), [0x31; 16]);
    assert_eq!(span.span_id(), [0x32; 8]);
    assert_eq!(span.observation_count(), 3);
    assert!(span.conflicted());
    assert_eq!(span.variants().len(), 2);
    assert_eq!(span.variants()[0].observation_count(), 2);
    assert_eq!(span.variants()[0].observation().observation(), &observation);
    assert_eq!(span.variants()[1].observation_count(), 1);
    assert_eq!(span.variants()[1].observation().observation(), &conflict);
    assert_eq!(
        span.structural_representative()
            .ok_or("missing structural representative")?
            .observation(),
        &observation
    );
    drop(logical);
    let byte_limited = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?).with_scanned_bytes(0),
    )?;
    assert!(byte_limited.spans().is_empty());
    assert!(!byte_limited.complete());
    assert_eq!(
        byte_limited.incompleteness(),
        TraceIncompleteness::ScannedBytesLimit
    );
    drop(byte_limited);
    let observed = store.scan_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
        &NeverCancelled,
        &NeverObserved,
    )?;
    assert_eq!(observed.spans().len(), 1);
    assert_eq!(observed.decoded_observations(), 3);
    drop(observed);
    let resumed = store.scan_physical(
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
    drop(resumed);
    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    let restarted_span = restarted
        .spans()
        .first()
        .ok_or("missing restarted logical span")?;
    assert_eq!(restarted_span.observation_count(), 3);
    assert_eq!(restarted_span.variants().len(), 2);
    assert!(restarted_span.conflicted());
    assert_eq!(restarted_span.variants()[0].observation_count(), 2);
    assert_eq!(restarted_span.variants()[1].observation_count(), 1);
    Ok(())
}

#[test]
fn summary_maintenance_applies_committed_deltas_quiesces_and_reopens_after_restart()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        TraceQuietPeriod::new(0)
            .expect_err("a zero quiescence interval is invalid")
            .code(),
        TraceStoreFailureCode::InvalidInput
    );
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(23)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
    )?;
    let trace = [0xa6; 16];
    let observation = |name: &str, span_id: [u8; 8]| {
        SpanObservation::checked_native(
            trace,
            span_id,
            None,
            name.to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Server,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0xa7; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    let original = observation("original", [0xa8; 8])?;
    let conflict = observation("conflict-with-longer-name", [0xa8; 8])?;
    let initial_receipt = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xa9; 16])?,
                vec![original.clone(), original, conflict],
            )?
            .into_store_block(),
    )?;
    let quiet_period = TraceQuietPeriod::new(5)?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        quiet_period,
        ScanLimit::new(2)?,
    )?;
    let maintenance_snapshot = ledger.snapshot()?;
    let inspection = authority.governor().inspect()?;
    let maintenance_observer = MaintenanceAdmissionObserver {
        governor: authority.governor(),
        interactive_baseline: inspection
            .outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail),
        maintenance_baseline: inspection
            .outstanding_for(positron_kernel::WorkClass::OrdinaryMaintenanceBackup),
        observed_maintenance_claim: Cell::new(false),
        observed_interactive: Cell::new(0),
        observed_maintenance: Cell::new(0),
    };
    let cancelled = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &AlwaysCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(104))),
    ) {
        Ok(_) => return Err("cancelled maintenance advanced its committed cursor".into()),
        Err(failure) => failure,
    };
    assert_eq!(cancelled.code(), TraceStoreFailureCode::Cancelled);
    {
        let first = maintainer.maintain(
            &store,
            &maintenance_snapshot,
            &NeverCancelled,
            &maintenance_observer,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(104))),
        )?;
        assert_eq!(first.applied_observations(), 2);
        assert!(!first.complete());
        assert_eq!(first.incompleteness(), TraceIncompleteness::ResultLimit);
        assert!(
            !first
                .summary(trace)
                .ok_or("partial summary is present")?
                .quiescent()
        );
        assert!(
            maintenance_observer.observed_maintenance_claim(),
            "summary replay class mismatch: interactive {} (baseline {}), maintenance {} (baseline {})",
            maintenance_observer.observed_interactive.get(),
            maintenance_observer.interactive_baseline,
            maintenance_observer.observed_maintenance.get(),
            maintenance_observer.maintenance_baseline,
        );
    }
    drop(maintenance_snapshot);
    {
        let first = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(104))),
        )?;
        assert_eq!(first.applied_observations(), 1);
        assert!(first.complete());
        assert_eq!(first.incompleteness(), TraceIncompleteness::None);
        let summary = first.summary(trace).ok_or("summary is present")?;
        assert_eq!(summary.trace_id(), trace);
        assert_eq!(summary.observation_count(), 3);
        assert_eq!(summary.logical_span_count(), 1);
        assert_eq!(summary.conflicted_span_count(), 1);
        assert!(
            !summary.truncated(),
            "ordinary observations must not be reported as truncated"
        );
        assert_eq!(
            summary.time_provenance(),
            TraceSummaryTimeProvenance::IngestTime
        );
        assert!(!summary.quiescent());
        assert_eq!(summary.first_seen().instant(), UnixNanoseconds::new(100));
        assert_eq!(summary.last_seen().instant(), UnixNanoseconds::new(100));
    }

    let quiescence_coverage = {
        let quiesced = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
        )?;
        assert!(
            quiesced
                .summary(trace)
                .ok_or("summary is present")?
                .quiescent()
        );
        assert_eq!(quiesced.applied_observations(), 0);
        assert!(quiesced.quiescence_complete());
        let coverage = quiesced.coverage();
        assert_eq!(
            coverage.applied_cursor(),
            Some((
                initial_receipt.position(),
                positron_domain::routing::RecordOrdinal::new(2)?,
            )),
            "the quiescent result must identify its final applied physical record"
        );
        assert!(coverage.physical_complete());
        assert!(coverage.quiescence_complete());
        assert_eq!(
            coverage
                .quiescence_checked_at()
                .map(|ingest_time| ingest_time.instant()),
            Some(UnixNanoseconds::new(105)),
            "the quiescent result must retain its kernel-assigned check time"
        );
        coverage
    };

    let stale_snapshot = ledger.snapshot()?;
    let late = observation("late", [0xa7; 8])?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(110))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xab; 16])?,
                vec![late],
            )?
            .into_store_block(),
    )?;
    let current_snapshot = ledger.snapshot()?;
    assert_eq!(
        quiescence_coverage.scope(),
        SegmentScope::new(tenant, SignalKind::Traces, shard)
    );
    assert_eq!(
        quiescence_coverage.catalog_generation(),
        stale_snapshot.catalog_generation()
    );
    assert_eq!(
        quiescence_coverage.catalog_identity(),
        stale_snapshot.catalog_identity(),
        "summary coverage must identify the exact authenticated catalog snapshot"
    );
    assert_eq!(quiescence_coverage.frontier(), stale_snapshot.frontier());
    assert!(
        quiescence_coverage.frontier() < current_snapshot.frontier(),
        "a quiescent result must retain the authenticated frontier it covered"
    );
    assert!(quiescence_coverage.physical_complete());
    {
        let reopened = maintainer.maintain(
            &store,
            &current_snapshot,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(111))),
        )?;
        let reopened_summary = reopened.summary(trace).ok_or("summary is present")?;
        assert_eq!(reopened.applied_observations(), 1);
        assert_eq!(reopened_summary.observation_count(), 4);
        assert_eq!(reopened_summary.logical_span_count(), 2);
        assert!(!reopened_summary.quiescent());
        assert_eq!(
            reopened_summary.last_seen().instant(),
            UnixNanoseconds::new(110)
        );
    }
    let stale = match maintainer.maintain(
        &store,
        &stale_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(111))),
    ) {
        Ok(_) => return Err("a stale snapshot rewound the shard-local summary cursor".into()),
        Err(failure) => failure,
    };
    assert_eq!(stale.code(), TraceStoreFailureCode::StaleGeneration);
    drop(maintainer);

    let mut recovered = TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        quiet_period,
        ScanLimit::new(16)?,
    )?;
    {
        let replayed = recovered.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(115))),
        )?;
        let replayed_summary = replayed
            .summary(trace)
            .ok_or("replayed summary is present")?;
        assert_eq!(replayed.applied_observations(), 4);
        assert_eq!(replayed_summary.observation_count(), 4);
        assert!(replayed_summary.quiescent());
    }
    let lifecycle_clock = LifecycleClock::new(SequenceLifecycleClock(Mutex::new(vec![
        UnixNanoseconds::new(100),
        UnixNanoseconds::new(115),
    ])));
    for _ in 0..2 {
        let maintained = recovered.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &lifecycle_clock,
        )?;
        assert!(
            maintained
                .summary(trace)
                .ok_or("backward lifecycle observation retained quiescence")?
                .quiescent()
        );
    }
    let unavailable = match recovered.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(SequenceLifecycleClock(Mutex::new(Vec::new()))),
    ) {
        Ok(_) => return Err("quiescence accepted an unavailable lifecycle clock".into()),
        Err(failure) => failure,
    };
    assert_eq!(unavailable.code(), TraceStoreFailureCode::ClockUnavailable);
    let other_shard = VirtualShardId::new(25)?;
    let other = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, other_shard),
        SegmentProtectionKey::from_owned(Box::new([0xac; 32])),
    )?;
    let mismatch = match recovered.maintain(
        &store,
        &other.snapshot()?,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(115))),
    ) {
        Ok(_) => return Err("a shard-local summary cursor scanned another shard".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        mismatch.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}

#[test]
fn summary_maintenance_rejects_a_same_generation_snapshot_with_a_different_identity()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(26)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let first_root = TemporaryRoot::new()?;
    let first_authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        first_root.path(),
        MountQualification::LocalHost,
    )?)?;
    let first_catalog = Catalog::open(
        &first_authority,
        InstanceId::new([0xad; 16])?,
        CatalogSecret::from_owned(Box::new([0xae; 32]), Box::new([0xaf; 32])),
    )?;
    let first_ledger = ActiveSegmentLedger::open(
        &first_authority,
        &first_catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb0; 32])),
    )?;
    let second_root = TemporaryRoot::new()?;
    let second_authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        second_root.path(),
        MountQualification::LocalHost,
    )?)?;
    let second_catalog = Catalog::open(
        &second_authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let second_ledger = ActiveSegmentLedger::open(
        &second_authority,
        &second_catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )?;
    let observation = |trace_id| {
        SpanObservation::checked_native(
            trace_id,
            [0xb5; 8],
            None,
            "snapshot-identity".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xb6; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    first_ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&first_authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xb8; 16])?,
                vec![observation([0xb7; 16])?],
            )?
            .into_store_block(),
    )?;
    second_ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&second_authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xba; 16])?,
                vec![observation([0xb9; 16])?],
            )?
            .into_store_block(),
    )?;
    let first_snapshot = first_ledger.snapshot()?;
    let second_snapshot = second_ledger.snapshot()?;
    assert_eq!(
        first_snapshot.catalog_generation(),
        second_snapshot.catalog_generation(),
        "the test requires colliding catalog sequence numbers"
    );
    assert_ne!(
        first_snapshot.catalog_identity(),
        second_snapshot.catalog_identity(),
        "independent authenticated catalogs have distinct identities"
    );
    let mut maintainer = TraceSummaryMaintainer::new(
        first_authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    maintainer.maintain(
        &store,
        &first_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    )?;
    let failure = match maintainer.maintain(
        &store,
        &second_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    ) {
        Ok(_) => return Err("a different authenticated catalog reused summary state".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), TraceStoreFailureCode::StaleGeneration);
    drop(maintainer);
    drop(second_snapshot);
    drop(first_snapshot);
    drop(first_ledger);
    drop(first_catalog);
    Ok(())
}

#[test]
fn summary_maintenance_rejects_a_lower_catalog_generation_and_retries_current_state()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(76)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let current_root = TemporaryRoot::new()?;
    let current_authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        current_root.path(),
        MountQualification::LocalHost,
    )?)?;
    let current_catalog = Catalog::open(
        &current_authority,
        InstanceId::new([0xc1; 16])?,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let current_key = SegmentProtectionKey::from_owned(Box::new([0xc4; 32]));
    let current_ledger = ActiveSegmentLedger::open(
        &current_authority,
        &current_catalog,
        scope,
        current_key.clone(),
    )?;
    let store = TraceStore::new();
    current_ledger.seal()?;
    let current_ledger =
        ActiveSegmentLedger::open(&current_authority, &current_catalog, scope, current_key)?;
    let current_snapshot = current_ledger.snapshot()?;
    let stale_root = TemporaryRoot::new()?;
    let stale_authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        stale_root.path(),
        MountQualification::LocalHost,
    )?)?;
    let stale_catalog = Catalog::open(
        &stale_authority,
        InstanceId::new([0xc9; 16])?,
        CatalogSecret::from_owned(Box::new([0xca; 32]), Box::new([0xcb; 32])),
    )?;
    let stale_ledger = ActiveSegmentLedger::open(
        &stale_authority,
        &stale_catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xcc; 32])),
    )?;
    let stale_snapshot = stale_ledger.snapshot()?;
    assert!(
        current_snapshot.catalog_generation() > stale_snapshot.catalog_generation(),
        "sealing must advance the authenticated current catalog beyond a fresh catalog"
    );
    let mut maintainer = TraceSummaryMaintainer::new(
        current_authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    {
        let current = maintainer.maintain(
            &store,
            &current_snapshot,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(current.applied_observations(), 0);
    }
    let refusal = match maintainer.maintain(
        &store,
        &stale_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    ) {
        Ok(_) => {
            return Err("a lower authenticated catalog generation reused summary state".into());
        },
        Err(failure) => failure,
    };
    assert_eq!(refusal.code(), TraceStoreFailureCode::StaleGeneration);
    let retry = maintainer.maintain(
        &store,
        &current_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
    )?;
    assert_eq!(retry.applied_observations(), 0);
    assert!(retry.complete());
    Ok(())
}

#[test]
fn summary_maintenance_retries_every_bounded_work_refusal_without_duplicate_summaries()
-> Result<(), Box<dyn Error>> {
    const SWEEP_CEILING: u64 = 256;

    let root = TemporaryRoot::new()?;
    let authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xcd; 16])?,
        CatalogSecret::from_owned(Box::new([0xce; 32]), Box::new([0xcf; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(77)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd0; 32])),
    )?;
    let trace = [0xd1; 16];
    let store = TraceStore::new();
    let profile = TraceStore::value_limit_profile();
    let details = SpanObservationDetails::checked_with_profile(
        SpanObservationDetailsInput {
            trace_state: String::new(),
            flags: 0,
            status: SpanStatus::checked(SpanStatusCode::Unset, String::new())?,
            events: vec![SpanEvent::checked_with_profile(
                EventTime::missing(),
                "retained-event".to_owned(),
                vec![SpanAttributeSet::checked_with_profile(
                    "event-values".to_owned(),
                    vec![CandidateAttributeValue::array(vec![
                        CandidateAttributeValue::string("event-visible".to_owned()),
                        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                            "nested".to_owned(),
                            CandidateAttributeValue::string("still-visible".to_owned()),
                        )]),
                    ])],
                    &profile,
                )?],
                0,
                &profile,
            )?],
            links: vec![SpanLink::checked_with_profile(
                [0xd5; 16],
                [0xd6; 8],
                String::new(),
                0,
                vec![SpanAttributeSet::checked_with_profile(
                    "link-values".to_owned(),
                    vec![CandidateAttributeValue::key_value_list(vec![
                        CandidateKeyValue::new(
                            "nested".to_owned(),
                            CandidateAttributeValue::array(vec![CandidateAttributeValue::string(
                                "still-visible".to_owned(),
                            )]),
                        ),
                    ])],
                    &profile,
                )?],
                0,
                &profile,
            )?],
            dropped_attributes_count: 0,
            dropped_events_count: 0,
            dropped_links_count: 0,
            resource: SpanResourceMetadata::checked(0, String::new())?,
            scope: SpanScopeMetadata::checked(String::new(), String::new(), 0, String::new())?,
        },
        &profile,
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xd2; 16])?,
                vec![SpanObservation::checked_native_with_details(
                    trace,
                    [0xd3; 8],
                    None,
                    "bounded-retry".to_owned(),
                    EventTime::missing(),
                    EventTime::missing(),
                    Vec::new(),
                    SpanKind::Internal,
                    SamplingDecision::Unknown,
                    positron_policy::PolicyProvenance::new(1, [0xd4; 32], Vec::new())?,
                    details,
                )?],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let measure = WorkMeter::new();
    {
        let mut maintainer = TraceSummaryMaintainer::new(
            authority.governor(),
            scope,
            TraceQuietPeriod::new(5)?,
            ScanLimit::new(1)?,
        )?;
        let completed = maintainer.maintain(
            &store,
            &snapshot,
            &NeverCancelled,
            &measure,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(completed.applied_observations(), 1);
        let summary = completed
            .summary(trace)
            .ok_or("completed maintenance must preserve one trace summary")?;
        assert_eq!(summary.observation_count(), 1);
        assert!(
            !summary.truncated(),
            "retained event and link values must not create a truncation quality flag"
        );
    }
    let allowances = measure.work();
    assert!(
        allowances > 0,
        "maintenance must observe bounded public work"
    );
    assert!(
        allowances <= SWEEP_CEILING,
        "the small public detail fixture consumed {allowances} units beyond the explicit bounded sweep ceiling"
    );
    let mut saw_refusal = false;
    for allowance in 0..allowances {
        let baseline = authority
            .governor()
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes);
        {
            let mut maintainer = TraceSummaryMaintainer::new(
                authority.governor(),
                scope,
                TraceQuietPeriod::new(5)?,
                ScanLimit::new(1)?,
            )?;
            let bounded = WorkBudget::exact(allowance);
            let applied = match maintainer.maintain(
                &store,
                &snapshot,
                &NeverCancelled,
                &bounded,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
            ) {
                Ok(maintenance) => {
                    let summary = maintenance
                        .summary(trace)
                        .ok_or("completed maintenance must preserve one trace summary")?;
                    assert_eq!(summary.observation_count(), 1);
                    assert!(
                        !summary.truncated(),
                        "retained event and link values must not create a truncation quality flag"
                    );
                    maintenance.applied_observations()
                },
                Err(failure) => {
                    assert_eq!(failure.code(), TraceStoreFailureCode::BudgetExhausted);
                    saw_refusal = true;
                    let retried = maintainer.maintain(
                        &store,
                        &snapshot,
                        &NeverCancelled,
                        &NeverObserved,
                        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                            100,
                        ))),
                    )?;
                    let summary = retried
                        .summary(trace)
                        .ok_or("retry must preserve one trace summary")?;
                    assert_eq!(
                        summary.observation_count(),
                        1,
                        "a bounded refusal must neither skip nor duplicate the physical observation"
                    );
                    assert!(
                        !summary.truncated(),
                        "a retry must preserve retained-detail quality"
                    );
                    retried.applied_observations()
                },
            };
            assert!(
                applied <= 1,
                "one physical observation cannot be applied twice"
            );
        }
        assert_eq!(
            authority
                .governor()
                .inspect()?
                .reserve_consumption(ResourceDimension::MemoryBytes),
            baseline,
            "dropping a retried maintenance owner must release its governed capacity"
        );
    }
    assert!(
        saw_refusal,
        "at least one bounded public work allowance must refuse"
    );
    Ok(())
}

#[test]
fn summary_maintenance_rejects_a_non_trace_scope_at_construction() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let failure = match TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(27)?),
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    ) {
        Ok(_) => return Err("a trace-summary maintainer accepted a Log Store scope".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), TraceStoreFailureCode::PhysicalScopeMismatch);
    Ok(())
}

#[test]
fn summary_maintenance_refusal_keeps_the_cursor_and_summary_unpublished()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(24)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xb5; 32])),
    )
    .map_err(|failure| format!("constrained ledger setup: {failure:?}"))?;
    let trace = [0xb6; 16];
    let observation = SpanObservation::checked_native(
        trace,
        [0xb8; 8],
        None,
        "capacity".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Sampled,
        positron_policy::PolicyProvenance::new(1, [0xb7; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    let receipt = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xb9; 16])?,
                vec![observation],
            )?
            .into_store_block(),
    )?;
    let scan_work = WorkMeter::new();
    let scan = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &scan_work,
    )?;
    assert!(scan.complete());
    drop(scan);
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    let blocker = ResizeBlocker::new(
        authority.governor(),
        tenant,
        scan_work
            .work()
            .checked_add(1)
            .ok_or("maintenance work boundary overflow")?,
    );
    let maintenance_baseline = authority
        .governor()
        .inspect()?
        .reserve_consumption(ResourceDimension::MemoryBytes);
    let failure = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &blocker,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    ) {
        Ok(_) => return Err("maintenance published a summary after resize refusal".into()),
        Err(failure) => failure,
    };
    assert!(blocker.armed(), "blocker armed after the physical scan");
    assert_eq!(
        failure.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );
    blocker.release();
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        maintenance_baseline,
        "a refused update must restore the maintainer's prior capacity before retry"
    );
    {
        let replay = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(replay.applied_observations(), 1);
        let summary = replay.summary(trace).ok_or("retry publishes the trace")?;
        assert_eq!(summary.observation_count(), 1);
    }
    let scan_work = WorkMeter::new();
    let no_delta_scan = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after_cursor(
            ScanLimit::new(1)?,
            receipt.position(),
            positron_domain::routing::RecordOrdinal::new(0)?,
        ),
        &NeverCancelled,
        &scan_work,
    )?;
    assert!(no_delta_scan.observations().is_empty());
    drop(no_delta_scan);
    let exhausted = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &WorkBudget::exact(scan_work.work()),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
    ) {
        Ok(_) => return Err("quiescence traversal bypassed the work budget".into()),
        Err(failure) => failure,
    };
    assert_eq!(exhausted.code(), TraceStoreFailureCode::BudgetExhausted);
    Ok(())
}

#[test]
fn summary_maintenance_retries_after_nested_truncation_budget_refusal() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x6b; 16])?,
        CatalogSecret::from_owned(Box::new([0x6c; 32]), Box::new([0x6d; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(75)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x6e; 32])),
    )?;
    let nested = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "retained".to_owned(),
        vec![CandidateAttributeValue::array(vec![
            CandidateAttributeValue::string("before".to_owned()),
            CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "child".to_owned(),
                CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::string("still-before".to_owned()),
                    CandidateAttributeValue::truncated(
                        CandidateAttributeValue::string("sanitized".to_owned()),
                        positron_domain::value::MarkerAction::TruncatedBytes,
                    ),
                ]),
            )]),
        ])],
    )
    .validate(TraceStore::value_limit_profile())?;
    let trace = [0x6f; 16];
    let observation = SpanObservation::checked_native(
        trace,
        [0x70; 8],
        None,
        "nested-truncation".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        vec![nested],
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x71; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x72; 16])?,
                vec![observation],
            )?
            .into_store_block(),
    )?;
    let physical_work = WorkMeter::new();
    let physical = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
        &NeverCancelled,
        &physical_work,
    )?;
    assert_eq!(physical.observations().len(), 1);
    drop(physical);
    let traversal_budget = physical_work
        .work()
        .checked_add(5)
        .ok_or("nested truncation traversal allowance overflow")?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    let refused = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &WorkBudget::exact(traversal_budget),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    ) {
        Ok(_) => return Err("nested traversal bypassed the maintenance budget".into()),
        Err(failure) => failure,
    };
    assert_eq!(refused.code(), TraceStoreFailureCode::BudgetExhausted);
    let retried = maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    )?;
    assert_eq!(retried.applied_observations(), 1);
    assert!(
        retried
            .summary(trace)
            .ok_or("retry publishes the nested trace")?
            .truncated()
    );
    Ok(())
}

#[test]
fn summary_maintenance_rejects_and_retries_at_the_outer_capacity_boundary()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x70; 16])?,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(70)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x73; 32])),
    )?;
    let store = TraceStore::new();
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    let append = |trace_value: u8, identity: u8| -> Result<_, Box<dyn Error>> {
        let observation = SpanObservation::checked_native(
            [trace_value; 16],
            [0x74; 8],
            None,
            "outer-capacity".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x75; 32], Vec::new())?,
        )?;
        Ok(ledger.append(
            store
                .prepare_unretained_for_test(
                    preparation_capacity(&authority, tenant)?,
                    &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                    tenant,
                    shard,
                    StoreBlockIdentity::new([identity; 16])?,
                    vec![observation],
                )?
                .into_store_block(),
        )?)
    };
    let mut fifth = None;
    for trace_value in 1..=5 {
        let receipt = append(trace_value, trace_value)?;
        if trace_value == 5 {
            fifth = Some(receipt);
        }
        let maintained = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(maintained.applied_observations(), 1);
        assert!(maintained.summary([trace_value; 16]).is_some());
    }
    let fifth_usage = authority
        .governor()
        .inspect()?
        .reserve_consumption(ResourceDimension::MemoryBytes);
    append(6, 6)?;
    let fifth = fifth.ok_or("fifth boundary receipt missing")?;
    let scan_work = WorkMeter::new();
    let physical = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after_cursor(
            ScanLimit::new(1)?,
            fifth.position(),
            positron_domain::routing::RecordOrdinal::new(0)?,
        ),
        &NeverCancelled,
        &scan_work,
    )?;
    assert_eq!(physical.observations().len(), 1);
    drop(physical);
    let blocker = ResizeBlocker::new(
        authority.governor(),
        tenant,
        scan_work
            .work()
            .checked_add(1)
            .ok_or("outer capacity work boundary overflow")?,
    );
    let failure = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &blocker,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    ) {
        Ok(_) => return Err("outer capacity growth bypassed resource admission".into()),
        Err(failure) => failure,
    };
    assert!(blocker.armed());
    assert_eq!(
        failure.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        fifth_usage,
        "a rejected outer-capacity update must retain neither a cursor advance nor governed memory"
    );
    let repeated = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &blocker,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    ) {
        Ok(_) => return Err("repeated outer capacity growth bypassed resource admission".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        repeated.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        fifth_usage,
        "repeated rejected growth must keep the governed capacity stable"
    );
    blocker.release();
    let retried = maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    )?;
    assert_eq!(retried.applied_observations(), 1);
    assert_eq!(
        retried
            .summary([6; 16])
            .ok_or("retry publishes the boundary trace")?
            .observation_count(),
        1
    );
    Ok(())
}

#[test]
fn summary_maintenance_large_semantic_update_is_budgeted_and_retries_from_the_prior_cursor()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xbc; 16])?,
        CatalogSecret::from_owned(Box::new([0xbd; 32]), Box::new([0xbe; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(26)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xbf; 32])),
    )?;
    let trace = [0xc0; 16];
    let observation = |prefix: char| {
        SpanObservation::checked_native(
            trace,
            [0xc1; 8],
            None,
            format!("{prefix}{}", "x".repeat(32_767)),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xc2; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    let first = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xc3; 16])?,
                vec![observation('a')?],
            )?
            .into_store_block(),
    )?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    {
        let initial = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(initial.applied_observations(), 1);
        assert_eq!(
            initial
                .summary(trace)
                .ok_or("initial large summary is present")?
                .observation_count(),
            1
        );
    }
    let second = observation('b')?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xc4; 16])?,
                vec![second.clone()],
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
            first.position(),
            positron_domain::routing::RecordOrdinal::new(0)?,
        ),
        &NeverCancelled,
        &physical_work,
    )?;
    assert_eq!(physical.observations().len(), 1);
    drop(physical);
    let semantic_work = WorkMeter::new();
    let profile = ValueLimitProfile::release_1_system_maximum();
    let semantic_bytes = super::codec::encoded_record_bytes_with_profile_observed(
        &profile,
        &second,
        &NeverCancelled,
        &semantic_work,
    )?
    .checked_sub(8)
    .ok_or("semantic bytes omit the ingest time")?;
    drop(
        super::codec::encode_semantic_observation_with_profile_observed(
            &profile,
            &second,
            semantic_bytes,
            &NeverCancelled,
            &semantic_work,
        )?,
    );
    let retained_copy_boundary = physical_work
        .work()
        .checked_add(semantic_work.work())
        .and_then(|work| work.checked_add(4))
        .ok_or("large maintenance work boundary overflow")?;
    let capacity_before_failure = authority
        .governor()
        .inspect()?
        .usage(ResourceDimension::MemoryBytes);
    let exhausted = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        // The physical scan, semantic sizing/encoding, handler, summary search,
        // and clone's span/variant entries fit. The first 4KiB retained-byte copy
        // must be observed before it can proceed.
        &WorkBudget::exact(retained_copy_boundary),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
    ) {
        Ok(_) => return Err("large summary work bypassed the maintenance budget".into()),
        Err(failure) => failure,
    };
    assert_eq!(exhausted.code(), TraceStoreFailureCode::BudgetExhausted);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        capacity_before_failure,
        "a failed staged update must restore its governed memory before retry"
    );
    let repeated = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &WorkBudget::exact(retained_copy_boundary),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
    ) {
        Ok(_) => return Err("repeated large summary work bypassed the maintenance budget".into()),
        Err(failure) => failure,
    };
    assert_eq!(repeated.code(), TraceStoreFailureCode::BudgetExhausted);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .usage(ResourceDimension::MemoryBytes),
        capacity_before_failure,
        "repeated failed staged updates must not retain extra governed memory"
    );
    {
        let retried = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
        )?;
        assert_eq!(retried.applied_observations(), 1);
        let summary = retried.summary(trace).ok_or("retry publishes the update")?;
        assert_eq!(summary.observation_count(), 2);
        assert_eq!(summary.logical_span_count(), 1);
        assert_eq!(summary.conflicted_span_count(), 1);
    }
    Ok(())
}

#[test]
fn summary_maintenance_continues_across_a_newer_authenticated_catalog_generation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd3; 16])?,
        CatalogSecret::from_owned(Box::new([0xd4; 32]), Box::new([0xd5; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(28)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd6; 32])),
    )?;
    let trace = [0xd7; 16];
    let observation = SpanObservation::checked_native(
        trace,
        [0xd8; 8],
        None,
        "catalog-rotation".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xd9; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xda; 16])?,
                vec![observation],
            )?
            .into_store_block(),
    )?;
    let first_snapshot = ledger.snapshot()?;
    let first_generation = first_snapshot.catalog_generation();
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(8)?,
    )?;
    {
        let initial = maintainer.maintain(
            &store,
            &first_snapshot,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(initial.applied_observations(), 1);
    }
    drop(first_snapshot);
    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd6; 32])),
    )?;
    let rotated_snapshot = reopened.snapshot()?;
    assert!(rotated_snapshot.catalog_generation() > first_generation);
    let continued = maintainer.maintain(
        &store,
        &rotated_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
    )?;
    assert_eq!(continued.applied_observations(), 0);
    assert!(
        continued
            .summary(trace)
            .ok_or("summary survives the catalog generation transition")?
            .quiescent()
    );
    Ok(())
}

#[test]
fn summary_maintenance_budgets_the_prior_summary_during_a_replacement_peak()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xdb; 16])?,
        CatalogSecret::from_owned(Box::new([0xdc; 32]), Box::new([0xdd; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(29)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xde; 32])),
    )?;
    let trace = [0xdf; 16];
    let observation = |prefix: char| {
        SpanObservation::checked_native(
            trace,
            [0xe0; 8],
            None,
            format!("{prefix}{}", "x".repeat(32_767)),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xe1; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    let first = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xe2; 16])?,
                vec![observation('a')?],
            )?
            .into_store_block(),
    )?;
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    {
        let initial = maintainer.maintain(
            &store,
            &ledger.snapshot()?,
            &NeverCancelled,
            &NeverObserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        )?;
        assert_eq!(initial.applied_observations(), 1);
    }
    let replacement = observation('b')?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0xe3; 16])?,
                vec![replacement.clone(), observation('c')?],
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
            first.position(),
            positron_domain::routing::RecordOrdinal::new(0)?,
        ),
        &NeverCancelled,
        &physical_work,
    )?;
    assert_eq!(physical.observations().len(), 1);
    assert!(!physical.complete());
    drop(physical);
    let semantic_work = WorkMeter::new();
    let profile = ValueLimitProfile::release_1_system_maximum();
    let semantic_bytes = super::codec::encoded_record_bytes_with_profile_observed(
        &profile,
        &replacement,
        &NeverCancelled,
        &semantic_work,
    )?
    .checked_sub(8)
    .ok_or("semantic bytes omit the ingest time")?;
    drop(
        super::codec::encode_semantic_observation_with_profile_observed(
            &profile,
            &replacement,
            semantic_bytes,
            &NeverCancelled,
            &semantic_work,
        )?,
    );
    let new_summary_boundary = physical_work
        .work()
        .checked_add(semantic_work.work())
        // Handler, trace lookup, two old-summary copies, span lookup, and
        // semantic comparison consume 25 units. The new two-variant summary
        // and physical admission checks consume six more. The retained prior
        // summary must still be observed before its rollback copy can drop.
        .and_then(|work| work.checked_add(31))
        .ok_or("replacement peak work boundary overflow")?;
    let exhausted = match maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &WorkBudget::exact(new_summary_boundary),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
    ) {
        Ok(_) => return Err("replacement peak omitted the retained prior summary".into()),
        Err(failure) => failure,
    };
    assert_eq!(exhausted.code(), TraceStoreFailureCode::BudgetExhausted);
    let retried = maintainer.maintain(
        &store,
        &ledger.snapshot()?,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
    )?;
    assert_eq!(retried.applied_observations(), 1);
    assert_eq!(
        retried
            .summary(trace)
            .ok_or("retry retains the replacement trace")?
            .observation_count(),
        2
    );
    Ok(())
}

#[test]
fn logical_scan_keeps_distinct_native_value_bits_as_conflicting_variants()
-> Result<(), Box<dyn Error>> {
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
    let attribute = |bits| {
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "duration".to_owned(),
            vec![CandidateAttributeValue::floating_point_bits(bits)],
        )
        .validate(ValueLimitProfile::release_1_system_maximum())
    };
    let observation = |attributes| {
        SpanObservation::checked_native(
            [0x61; 16],
            [0x62; 8],
            None,
            "native-value".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            attributes,
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x90; 32], Vec::new())?,
        )
    };
    let positive_zero = observation(vec![attribute(0.0_f64.to_bits())?])?;
    let negative_zero = observation(vec![attribute((-0.0_f64).to_bits())?])?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x69; 16])?,
                vec![positive_zero.clone(), positive_zero, negative_zero],
            )?
            .into_store_block(),
    )?;
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
    )?;
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(span.observation_count(), 3);
    assert_eq!(span.variants().len(), 2);
    assert_eq!(span.variants()[0].observation_count(), 2);
    assert_eq!(span.variants()[1].observation_count(), 1);
    assert!(span.conflicted());
    Ok(())
}

#[test]
fn logical_scan_preserves_native_attribute_type_and_namespace_variants()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x28; 16])?,
        CatalogSecret::from_owned(Box::new([0x38; 32]), Box::new([0x48; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(18)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x68; 32])),
    )?;
    let attribute = |namespace, value| {
        AttributeOccurrenceSetCandidate::new(namespace, "enabled".to_owned(), vec![value])
            .validate(ValueLimitProfile::release_1_system_maximum())
    };
    let observation = |attributes| {
        SpanObservation::checked_native(
            [0x71; 16],
            [0x72; 8],
            None,
            "semantic-identity".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            attributes,
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xa0; 32], Vec::new())?,
        )
    };
    let record_boolean = observation(vec![attribute(
        AttributeNamespace::Record,
        CandidateAttributeValue::boolean(true),
    )?])?;
    let resource_boolean = observation(vec![attribute(
        AttributeNamespace::Resource,
        CandidateAttributeValue::boolean(true),
    )?])?;
    let record_string = observation(vec![attribute(
        AttributeNamespace::Record,
        CandidateAttributeValue::string("true".to_owned()),
    )?])?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x79; 16])?,
                vec![
                    record_boolean.clone(),
                    record_boolean.clone(),
                    resource_boolean.clone(),
                    record_string.clone(),
                ],
            )?
            .into_store_block(),
    )?;
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(4)?),
    )?;
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(logical.spans().len(), 1);
    assert_eq!(span.observation_count(), 4);
    assert_eq!(span.variants().len(), 3);
    let variant = |expected: &SpanObservation| {
        span.variants()
            .iter()
            .find(|variant| variant.observation().observation() == expected)
            .ok_or("missing semantic variant")
    };
    assert_eq!(variant(&record_boolean)?.observation_count(), 2);
    assert_eq!(variant(&resource_boolean)?.observation_count(), 1);
    assert_eq!(variant(&record_string)?.observation_count(), 1);
    assert!(span.conflicted());
    Ok(())
}

#[test]
fn logical_scan_preserves_event_link_and_provenance_only_conflicts() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x29; 16])?,
        CatalogSecret::from_owned(Box::new([0x39; 32]), Box::new([0x49; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(19)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x69; 32])),
    )?;
    let details = |events, links| {
        SpanObservationDetails::checked(SpanObservationDetailsInput {
            trace_state: String::new(),
            flags: 0,
            status: SpanStatus::checked(SpanStatusCode::Unset, String::new())?,
            events,
            links,
            dropped_attributes_count: 0,
            dropped_events_count: 0,
            dropped_links_count: 0,
            resource: SpanResourceMetadata::checked(0, String::new())?,
            scope: SpanScopeMetadata::checked(String::new(), String::new(), 0, String::new())?,
        })
    };
    let base_details = details(Vec::new(), Vec::new())?;
    let event_details = details(
        vec![SpanEvent::checked(
            EventTime::missing(),
            "event-only".to_owned(),
            Vec::new(),
            0,
        )?],
        Vec::new(),
    )?;
    let link_details = details(
        Vec::new(),
        vec![SpanLink::checked(
            [0x91; 16],
            [0x92; 8],
            String::new(),
            0,
            Vec::new(),
            0,
        )?],
    )?;
    let observation = |details, provenance| {
        SpanObservation::checked_native_with_details(
            [0x81; 16],
            [0x82; 8],
            None,
            "detail-identity".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            provenance,
            details,
        )
    };
    let base = observation(
        base_details.clone(),
        positron_policy::PolicyProvenance::new(1, [0xa1; 32], Vec::new())?,
    )?;
    let event_only = observation(
        event_details,
        positron_policy::PolicyProvenance::new(1, [0xa1; 32], Vec::new())?,
    )?;
    let link_only = observation(
        link_details,
        positron_policy::PolicyProvenance::new(1, [0xa1; 32], Vec::new())?,
    )?;
    let provenance_only = observation(
        base_details,
        positron_policy::PolicyProvenance::new(2, [0xa2; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x89; 16])?,
                vec![
                    base.clone(),
                    base.clone(),
                    event_only.clone(),
                    link_only.clone(),
                    provenance_only.clone(),
                ],
            )?
            .into_store_block(),
    )?;
    let logical = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(5)?),
    )?;
    let span = logical.spans().first().ok_or("missing logical span")?;
    assert_eq!(logical.spans().len(), 1);
    assert_eq!(span.observation_count(), 5);
    assert_eq!(span.variants().len(), 4);
    let variant = |expected: &SpanObservation| {
        span.variants()
            .iter()
            .find(|variant| variant.observation().observation() == expected)
            .ok_or("missing semantic variant")
    };
    assert_eq!(variant(&base)?.observation_count(), 2);
    assert_eq!(variant(&event_only)?.observation_count(), 1);
    assert_eq!(variant(&link_only)?.observation_count(), 1);
    assert_eq!(variant(&provenance_only)?.observation_count(), 1);
    assert!(span.conflicted());
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
            SpanObservation::checked_native(
                [0x41; 16],
                [id.saturating_add(1); 8],
                None,
                format!("span-{id}"),
                EventTime::missing(),
                EventTime::missing(),
                Vec::new(),
                SpanKind::Internal,
                SamplingDecision::Unknown,
                positron_policy::PolicyProvenance::new(1, [0x82; 32], Vec::new()).unwrap(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first_receipt = ledger.append(
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
    let third_observation = SpanObservation::checked_native(
        [0x43; 16],
        [0x52; 8],
        None,
        "third-block".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x83; 32], Vec::new()).unwrap(),
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(102))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x6c; 16])?,
                vec![third_observation],
            )?
            .into_store_block(),
    )?;
    let second_observation = SpanObservation::checked_native(
        [0x42; 16],
        [0x51; 8],
        None,
        "second-block".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x84; 32], Vec::new()).unwrap(),
    )?;
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x6b; 16])?,
                vec![second_observation],
            )?
            .into_store_block(),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.spans().len(), 1);
    assert_eq!(result.decoded_observations(), 1);
    assert!(!result.complete());
    assert_eq!(
        result.incompleteness(),
        super::TraceIncompleteness::ResultLimit
    );
    drop(result);
    let bounded_search = store.search(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceSearch::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(bounded_search.spans().len(), 1);
    assert!(!bounded_search.complete());
    assert_eq!(
        bounded_search.incompleteness(),
        super::TraceIncompleteness::ResultLimit
    );
    let next_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::after(ScanLimit::new(1)?, first_receipt.position()),
    )?;
    assert_eq!(next_result.spans().len(), 1);
    assert_eq!(next_result.decoded_observations(), 1);
    assert!(!next_result.complete());
    let roomy_result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(roomy_result.spans().len(), 5);
    assert_eq!(roomy_result.decoded_observations(), 5);
    assert!(roomy_result.complete());
    assert!(roomy_result.scanned_bytes() > 0);
    assert!(roomy_result.retained_size_bytes() > 0);
    Ok(())
}
