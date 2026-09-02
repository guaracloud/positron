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
    let base = store.scan_observed(
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
    let one = store.scan_observed(
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
    let exact = store.scan_observed(
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
    let page = store.scan(
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
