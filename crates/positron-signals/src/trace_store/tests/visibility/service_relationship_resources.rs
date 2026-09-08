use super::super::*;
use crate::TraceStoreFailure;
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

struct WorkCounter(AtomicU64);

impl WorkCounter {
    fn work(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl ScanObserver for WorkCounter {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |work| {
                work.checked_add(units)
            })
            .map(|_| ())
            .map_err(|_| ScanObservationFailureCode::BudgetExhausted)
    }
}

struct ExhaustAfterWork(Cell<u64>);

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

struct SharedCancellation(Arc<AtomicBool>);

impl ScanCancellation for SharedCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

struct CancelAfterWork {
    limit: u64,
    observed: AtomicU64,
    cancelled: Arc<AtomicBool>,
}

impl ScanObserver for CancelAfterWork {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let observed = self
            .observed
            .fetch_add(units, Ordering::Relaxed)
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        if observed > self.limit {
            self.cancelled.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[test]
fn service_identity_attribute_traversal_consumes_work_and_honors_cancellation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(101)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xa4; 32])),
    )?;
    let service = |name: &str| {
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Resource,
            "service.name".to_owned(),
            vec![CandidateAttributeValue::string(name.to_owned())],
        )
        .validate(ValueLimitProfile::release_1_system_maximum())
        .map_err(TraceStoreFailure::domain)
    };
    let observation = |trace_id, span_id, parent_span_id, attributes| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            parent_span_id,
            "operation".to_owned(),
            EventTime::received(UnixNanoseconds::new(1), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(2), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            attributes,
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0xa5; 32], Vec::new())?,
        )
    };
    let baseline = [0xa6; 16];
    let traversed = [0xa7; 16];
    let mut traversed_attributes = Vec::new();
    for index in 0_u8..32 {
        traversed_attributes.push(
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Resource,
                format!("unrelated-{index}"),
                vec![CandidateAttributeValue::string("value".to_owned())],
            )
            .validate(ValueLimitProfile::release_1_system_maximum())
            .map_err(TraceStoreFailure::domain)?,
        );
    }
    traversed_attributes.push(service("inventory")?);
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0xa8; 16])?,
                vec![
                    observation(baseline, [0x01; 8], None, vec![service("checkout")?])?,
                    observation(
                        baseline,
                        [0x02; 8],
                        Some([0x01; 8]),
                        vec![service("inventory")?],
                    )?,
                    observation(traversed, [0x01; 8], None, vec![service("checkout")?])?,
                    observation(traversed, [0x02; 8], Some([0x01; 8]), traversed_attributes)?,
                ],
            )?
            .into_store_block(),
    )?;

    let counter = WorkCounter(AtomicU64::new(0));
    let mut baseline_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        baseline,
        TraceSearch::all(ScanLimit::new(4)?),
    )?;
    let baseline_structure = baseline_result.analyze_structure(&NeverCancelled, &counter)?;
    assert!(baseline_structure.service_relationships().complete());
    let baseline_work = counter.work();
    assert!(baseline_work > 0);
    drop(baseline_structure);
    drop(baseline_result);

    let before_budget_failure = authority.governor().inspect()?.outstanding_total();
    let mut budget_limited = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        traversed,
        TraceSearch::all(ScanLimit::new(4)?),
    )?;
    let budget_failure = budget_limited
        .analyze_structure(&NeverCancelled, &ExhaustAfterWork(Cell::new(baseline_work)))
        .expect_err("service identity traversal must consume cumulative work budget");
    assert_eq!(
        budget_failure.code(),
        TraceStoreFailureCode::BudgetExhausted
    );
    drop(budget_limited);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_budget_failure
    );

    let before_cancellation = authority.governor().inspect()?.outstanding_total();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut cancellation_limited = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        traversed,
        TraceSearch::all(ScanLimit::new(4)?),
    )?;
    let cancellation_failure = cancellation_limited
        .analyze_structure(
            &SharedCancellation(Arc::clone(&cancelled)),
            &CancelAfterWork {
                limit: baseline_work,
                observed: AtomicU64::new(0),
                cancelled: Arc::clone(&cancelled),
            },
        )
        .expect_err("service identity traversal must poll observer-triggered cancellation");
    assert_eq!(
        cancellation_failure.code(),
        TraceStoreFailureCode::Cancelled
    );
    drop(cancellation_limited);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_cancellation
    );
    Ok(())
}
