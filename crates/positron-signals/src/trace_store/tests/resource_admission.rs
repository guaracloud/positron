use super::*;
use std::sync::Arc;

struct WorkBudget {
    limit: Option<u64>,
    observed: AtomicU64,
}

impl WorkBudget {
    const fn unlimited() -> Self {
        Self {
            limit: None,
            observed: AtomicU64::new(0),
        }
    }

    const fn exact(limit: u64) -> Self {
        Self {
            limit: Some(limit),
            observed: AtomicU64::new(0),
        }
    }

    fn work(&self) -> u64 {
        self.observed.load(Ordering::Relaxed)
    }
}

impl ScanObserver for WorkBudget {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let current = self.work();
        let next = current
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        if self.limit.is_some_and(|limit| next > limit) {
            return Err(ScanObservationFailureCode::BudgetExhausted);
        }
        self.observed.store(next, Ordering::Relaxed);
        Ok(())
    }
}

struct SharedCancellation(Arc<AtomicU64>);

impl ScanCancellation for SharedCancellation {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed) != 0
    }
}

struct CancelAfterFirstRecord(Arc<AtomicU64>);

impl ScanObserver for CancelAfterFirstRecord {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_decoded_records(&self, _records: u64) -> Result<(), ScanObservationFailureCode> {
        self.0.store(1, Ordering::Relaxed);
        Ok(())
    }
}

struct CancelAfterWork {
    limit: u64,
    observed: AtomicU64,
    cancelled: Arc<AtomicU64>,
}

impl ScanObserver for CancelAfterWork {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let next = self
            .observed
            .fetch_add(units, Ordering::Relaxed)
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        if next > self.limit {
            self.cancelled.store(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[test]
fn consolidation_observes_post_decode_budget_and_cancellation_without_reservation_drift()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x95; 16])?,
        CatalogSecret::from_owned(Box::new([0xa5; 32]), Box::new([0xb5; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(15)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc5; 32])),
    )?;
    let retry = SpanObservation::checked_native(
        [0xd5; 16],
        [0xe5; 8],
        None,
        "retry".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xf5; 32], Vec::new())?,
    )?;
    let conflict = SpanObservation::checked_native(
        [0xd5; 16],
        [0xe5; 8],
        None,
        "conflict".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xf6; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x45; 16])?,
                vec![retry.clone(), retry, conflict],
            )?
            .into_store_block(),
    )?;
    let physical_work = WorkBudget::unlimited();
    let physical = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
        &NeverCancelled,
        &physical_work,
    )?;
    assert_eq!(physical.observations().len(), 3);
    let decode_work = physical_work.work();
    drop(physical);

    let complete_work = WorkBudget::unlimited();
    let complete = store.scan_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(3)?),
        &NeverCancelled,
        &complete_work,
    )?;
    assert_eq!(complete.spans().len(), 1);
    assert_eq!(complete.spans()[0].observation_count(), 3);
    drop(complete);
    let total_work = complete_work.work();
    let consolidation_work = total_work
        .checked_sub(decode_work)
        .ok_or("logical work did not include physical decode")?;
    assert!(consolidation_work > 1);
    let partial_budget = decode_work
        .checked_add(consolidation_work / 2)
        .ok_or("partial consolidation budget overflow")?;
    assert!(partial_budget > decode_work);
    assert!(partial_budget < total_work);
    let before_partial = authority.governor().inspect()?.outstanding_total();
    let partial_observer = WorkBudget::exact(partial_budget);
    let partial_failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(3)?),
            &NeverCancelled,
            &partial_observer,
        )
        .expect_err("a partial post-decode budget must interrupt consolidation");
    assert_eq!(
        partial_failure.code(),
        TraceStoreFailureCode::BudgetExhausted
    );
    assert_eq!(partial_observer.work(), partial_budget);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_partial
    );

    let before_budget = authority.governor().inspect()?.outstanding_total();
    let exhausted = WorkBudget::exact(decode_work);
    let budget_failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(3)?),
            &NeverCancelled,
            &exhausted,
        )
        .expect_err("logical consolidation must consume work after physical decode");
    assert_eq!(
        budget_failure.code(),
        TraceStoreFailureCode::BudgetExhausted
    );
    assert_eq!(
        budget_failure.completion_state(),
        positron_kernel::LedgerCompletionState::RejectedBeforeMutation
    );
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_budget
    );

    let cancelled = Arc::new(AtomicU64::new(0));
    let cancellation = SharedCancellation(Arc::clone(&cancelled));
    let cancel_after_decode = CancelAfterWork {
        limit: decode_work,
        observed: AtomicU64::new(0),
        cancelled,
    };
    let before_cancel = authority.governor().inspect()?.outstanding_total();
    let cancellation_failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(3)?),
            &cancellation,
            &cancel_after_decode,
        )
        .expect_err("logical consolidation must poll cancellation after physical decode");
    assert_eq!(
        cancellation_failure.code(),
        TraceStoreFailureCode::Cancelled
    );
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_cancel
    );
    Ok(())
}

#[test]
fn maximum_native_payload_budget_interrupts_semantic_key_construction() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x96; 16])?,
        CatalogSecret::from_owned(Box::new([0xa6; 32]), Box::new([0xb6; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(16)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc6; 32])),
    )?;
    let attribute = |last_byte| {
        let mut bytes = vec![0x11; 65_535];
        bytes.push(last_byte);
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![CandidateAttributeValue::bytes(bytes)],
        )
        .validate(ValueLimitProfile::release_1_system_maximum())
    };
    let observation = |attributes| {
        SpanObservation::checked_native(
            [0xd6; 16],
            [0xe6; 8],
            None,
            "maximum-payload".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            attributes,
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0xf6; 32], Vec::new())?,
        )
    };
    let first = observation(vec![attribute(0x11)?])?;
    let second = observation(vec![attribute(0x12)?])?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x46; 16])?,
                vec![first, second],
            )?
            .into_store_block(),
    )?;
    let decode_work = WorkBudget::unlimited();
    let physical = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(2)?),
        &NeverCancelled,
        &decode_work,
    )?;
    drop(physical);
    let maximum_inline_work = decode_work
        .work()
        .checked_add(16)
        .ok_or("work limit overflow")?;
    let constrained = WorkBudget::exact(maximum_inline_work);
    let before = authority.governor().inspect()?.outstanding_total();
    let failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(2)?),
            &NeverCancelled,
            &constrained,
        )
        .expect_err("maximum payload key construction must charge bounded work");
    assert_eq!(failure.code(), TraceStoreFailureCode::BudgetExhausted);
    assert_eq!(constrained.work(), maximum_inline_work);
    assert_eq!(authority.governor().inspect()?.outstanding_total(), before);
    Ok(())
}

#[test]
fn tight_governor_refuses_logical_consolidation_before_extra_sort_buffers_allocate()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x97; 16])?,
        CatalogSecret::from_owned(Box::new([0xa7; 32]), Box::new([0xb7; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(17)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc7; 32])),
    )?;
    let observation = SpanObservation::checked_native(
        [0xd7; 16],
        [0xe7; 8],
        None,
        "tight-governor".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xf7; 32], Vec::new())?,
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x47; 16])?,
                vec![observation; 512],
            )?
            .into_store_block(),
    )?;
    let held = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 4_000_000)?,
    )?)?;
    let before = authority.governor().inspect()?.outstanding_total();
    let refusal = store
        .scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(512)?),
        )
        .expect_err("logical scan must admit its complete sort peak before allocating");
    assert_eq!(
        refusal.code(),
        TraceStoreFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(authority.governor().inspect()?.outstanding_total(), before);
    drop(held);
    let complete = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(512)?),
    )?;
    assert_eq!(complete.spans().len(), 1);
    assert_eq!(complete.spans()[0].observation_count(), 512);
    Ok(())
}

#[test]
fn policy_rules_consume_their_exact_scan_work_budget() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0xa1; 32]), Box::new([0xb1; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(12)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0xc1; 32])),
    )?;
    let store = TraceStore::new();
    let append = |identity: u8, rules: Vec<String>| {
        let observation = SpanObservation::checked_native(
            [0xd1; 16],
            [identity; 8],
            None,
            "policy-budget".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [identity; 32], rules)?,
        )?;
        Ok::<_, Box<dyn Error>>(
            ledger.append(
                store
                    .prepare_unretained_for_test(
                        preparation_capacity(&authority, tenant)?,
                        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                            i64::from(identity),
                        ))),
                        tenant,
                        shard,
                        positron_kernel::StoreBlockIdentity::new([identity; 16])?,
                        vec![observation],
                    )?
                    .into_store_block(),
            )?,
        )
    };
    let no_rules = append(1, Vec::new())?;
    let one_rule = append(2, vec!["rule.one".to_owned()])?;
    let two_rules = append(3, vec!["rule.one".to_owned(), "rule.two".to_owned()])?;

    let base_observer = WorkBudget::unlimited();
    let base = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::through(ScanLimit::new(1)?, no_rules.position()),
        &NeverCancelled,
        &base_observer,
    )?;
    assert!(base.complete());
    let base_work = base_observer.work();

    let one_observer = WorkBudget::unlimited();
    let one = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::between(ScanLimit::new(1)?, no_rules.position(), one_rule.position()),
        &NeverCancelled,
        &one_observer,
    )?;
    assert!(one.complete());
    let one_work = one_observer.work();
    assert!(one_work > base_work);

    let exact_observer = WorkBudget::exact(one_work);
    let exact = store.scan_physical_observed(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::between(ScanLimit::new(1)?, no_rules.position(), one_rule.position()),
        &NeverCancelled,
        &exact_observer,
    )?;
    assert!(exact.complete());
    assert_eq!(exact_observer.work(), one_work);

    let before_failure = authority.governor().inspect()?.outstanding_total();
    let two_observer = WorkBudget::exact(one_work);
    let failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::between(
                ScanLimit::new(1)?,
                one_rule.position(),
                two_rules.position(),
            ),
            &NeverCancelled,
            &two_observer,
        )
        .expect_err("the additional policy rule must consume work");
    assert_eq!(failure.code(), TraceStoreFailureCode::BudgetExhausted);
    assert_eq!(
        failure.completion_state(),
        positron_kernel::LedgerCompletionState::RejectedBeforeMutation
    );
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_failure
    );
    Ok(())
}

#[test]
fn scan_stages_admission_before_recursive_work_and_stops_at_page_boundaries()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x92; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xb2; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(13)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xc2; 32])),
    )?;
    let store = TraceStore::new();
    let observation = SpanObservation::checked_native(
        [0xd2; 16],
        [0xe2; 8],
        None,
        "staged".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        Vec::new(),
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0xf2; 32], Vec::new())?,
    )?;
    let first = ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x42; 16])?,
                vec![observation],
            )?
            .into_store_block(),
    )?;
    ledger.append(positron_kernel::PreparedStoreBlock::new(
        scope,
        positron_kernel::StoreBlockIdentity::new([0x43; 16])?,
        b"PTRCBL01".to_vec(),
    )?)?;

    let before_budget = authority.governor().inspect()?.outstanding_total();
    let zero_budget = WorkBudget::exact(0);
    let failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
            &NeverCancelled,
            &zero_budget,
        )
        .expect_err("zero scan budget must stop before recursive preflight");
    assert_eq!(failure.code(), TraceStoreFailureCode::BudgetExhausted);
    assert_eq!(zero_budget.work(), 0);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_budget
    );

    let before_page = authority.governor().inspect()?.outstanding_total();
    let page = store.scan_physical(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(page.observations().len(), 1);
    assert!(!page.complete());
    assert_eq!(page.incompleteness(), TraceIncompleteness::ResultLimit);
    assert_eq!(page.observations()[0].commit_position(), first.position());
    drop(page);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_page
    );

    let cancelled = Arc::new(AtomicU64::new(0));
    let cancellation = SharedCancellation(Arc::clone(&cancelled));
    let observer = CancelAfterFirstRecord(Arc::clone(&cancelled));
    let before_cancel = authority.governor().inspect()?.outstanding_total();
    let failure = store
        .scan_observed(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(2)?),
            &cancellation,
            &observer,
        )
        .expect_err("cancellation after one block must stop before the next");
    assert_eq!(failure.code(), TraceStoreFailureCode::Cancelled);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        before_cancel
    );
    Ok(())
}
