use super::super::*;
use crate::{TraceQuietPeriod, TraceSummary, TraceSummaryMaintainer};

#[test]
fn trace_by_id_only_exposes_a_summary_when_coverage_matches_its_snapshot()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(61)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x64; 32])),
    )?;
    let trace_id = [0x65; 16];
    let observation = |span_id, name| {
        SpanObservation::checked_native(
            trace_id,
            span_id,
            None,
            name,
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x66; 32], Vec::new())?,
        )
    };
    let store = TraceStore::new();
    let append = |identity, ingest_time, observation| {
        ledger.append(
            store
                .prepare_unretained_for_test(
                    preparation_capacity(&authority, tenant)?,
                    &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                        ingest_time,
                    ))),
                    tenant,
                    shard,
                    StoreBlockIdentity::new([identity; 16])?,
                    vec![observation],
                )?
                .into_store_block(),
        )?;
        Ok::<(), Box<dyn Error>>(())
    };
    append(0x67, 100, observation([0x21; 8], "first".to_owned())?)?;

    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(2)?,
    )?;
    let snapshot_a = ledger.snapshot()?;
    let stale = maintainer.maintain(
        &store,
        &snapshot_a,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
    )?;
    assert!(stale.complete());
    assert!(stale.quiescence_complete());
    assert!(stale.summary(trace_id).is_some_and(TraceSummary::quiescent));

    append(0x68, 110, observation([0x22; 8], "late".to_owned())?)?;
    let snapshot_b = ledger.snapshot()?;
    let stale_result = store.trace_by_id_with_summary(
        authority.governor(),
        tenant,
        &snapshot_b,
        trace_id,
        TraceSearch::all(ScanLimit::new(2)?),
        &stale,
    )?;
    assert!(matches!(
        stale_result.summary(),
        crate::TraceByIdSummary::Pending(crate::TraceByIdSummaryPending::FrontierMismatch)
    ));
    drop(stale_result);
    drop(stale);

    let current = maintainer.maintain(
        &store,
        &snapshot_b,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(115))),
    )?;
    let current_result = store.trace_by_id_with_summary(
        authority.governor(),
        tenant,
        &snapshot_b,
        trace_id,
        TraceSearch::all(ScanLimit::new(2)?),
        &current,
    )?;
    match current_result.summary() {
        crate::TraceByIdSummary::Available { summary, coverage } => {
            assert_eq!(summary.trace_id(), trace_id);
            assert_eq!(summary.first_seen().instant(), UnixNanoseconds::new(100));
            assert_eq!(summary.last_seen().instant(), UnixNanoseconds::new(110));
            assert_eq!(summary.observation_count(), 2);
            assert_eq!(summary.logical_span_count(), 2);
            assert!(summary.quiescent());
            assert!(!summary.truncated());
            assert!(coverage.physical_complete());
            assert!(coverage.quiescence_complete());
            assert_eq!(coverage.scope(), scope);
            assert_eq!(coverage.catalog_identity(), snapshot_b.catalog_identity());
            assert_eq!(
                coverage.catalog_generation(),
                snapshot_b.catalog_generation()
            );
            assert_eq!(coverage.frontier(), snapshot_b.frontier());
            assert!(coverage.applied_cursor().is_some());
        },
        pending => return Err(format!("current summary unexpectedly pending: {pending:?}").into()),
    }
    drop(current_result);

    let unbound_result = store.trace_by_id(
        authority.governor(),
        tenant,
        &snapshot_b,
        trace_id,
        TraceSearch::all(ScanLimit::new(2)?),
    )?;
    assert!(matches!(
        unbound_result.summary(),
        crate::TraceByIdSummary::Pending(crate::TraceByIdSummaryPending::NoMaintenance)
    ));
    drop(unbound_result);

    let cancelled = store
        .trace_by_id_observed_with_summary(
            authority.governor(),
            tenant,
            &snapshot_b,
            trace_id,
            TraceSearch::all(ScanLimit::new(2)?),
            &AlwaysCancelled,
            &NeverObserved,
            &current,
        )
        .expect_err("summary binding must preserve caller cancellation");
    assert_eq!(cancelled.code(), TraceStoreFailureCode::Cancelled);
    let exhausted = store
        .trace_by_id_observed_with_summary(
            authority.governor(),
            tenant,
            &snapshot_b,
            trace_id,
            TraceSearch::all(ScanLimit::new(2)?),
            &NeverCancelled,
            &WorkBudgetExhausted,
            &current,
        )
        .expect_err("summary binding must preserve caller work accounting");
    assert_eq!(exhausted.code(), TraceStoreFailureCode::BudgetExhausted);

    let absent_result = store.trace_by_id_with_summary(
        authority.governor(),
        tenant,
        &snapshot_b,
        [0x7f; 16],
        TraceSearch::all(ScanLimit::new(2)?),
        &current,
    )?;
    assert!(matches!(
        absent_result.summary(),
        crate::TraceByIdSummary::Pending(crate::TraceByIdSummaryPending::Absent)
    ));
    drop(absent_result);

    let mut partial_maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    let partial = partial_maintainer.maintain(
        &store,
        &snapshot_b,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(115))),
    )?;
    assert!(!partial.complete());
    let partial_result = store.trace_by_id_with_summary(
        authority.governor(),
        tenant,
        &snapshot_b,
        trace_id,
        TraceSearch::all(ScanLimit::new(2)?),
        &partial,
    )?;
    assert!(matches!(
        partial_result.summary(),
        crate::TraceByIdSummary::Pending(crate::TraceByIdSummaryPending::IncompleteCoverage)
    ));
    drop(partial_result);
    drop(partial);

    let other_scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(62)?);
    let other = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        other_scope,
        SegmentProtectionKey::from_owned(Box::new([0x69; 32])),
    )?;
    other.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(120))),
                tenant,
                other_scope.shard_id(),
                StoreBlockIdentity::new([0x6a; 16])?,
                vec![observation([0x23; 8], "other-scope".to_owned())?],
            )?
            .into_store_block(),
    )?;
    let cross_scope = store.trace_by_id_with_summary(
        authority.governor(),
        tenant,
        &other.snapshot()?,
        trace_id,
        TraceSearch::all(ScanLimit::new(1)?),
        &current,
    )?;
    assert!(matches!(
        cross_scope.summary(),
        crate::TraceByIdSummary::Pending(crate::TraceByIdSummaryPending::ScopeMismatch)
    ));
    Ok(())
}

#[test]
fn trace_by_id_rejects_summary_from_another_authenticated_catalog() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(63)?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let first_root = TemporaryRoot::new()?;
    let first_authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        first_root.path(),
        MountQualification::LocalHost,
    )?)?;
    let first_catalog = Catalog::open(
        &first_authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let first_ledger = ActiveSegmentLedger::open(
        &first_authority,
        &first_catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    let second_root = TemporaryRoot::new()?;
    let second_authority = establish_kernel_authority(PrimaryDataVolume::acquire(
        second_root.path(),
        MountQualification::LocalHost,
    )?)?;
    let second_catalog = Catalog::open(
        &second_authority,
        InstanceId::new([0x75; 16])?,
        CatalogSecret::from_owned(Box::new([0x76; 32]), Box::new([0x77; 32])),
    )?;
    let second_ledger = ActiveSegmentLedger::open(
        &second_authority,
        &second_catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x78; 32])),
    )?;
    let store = TraceStore::new();
    let observation = |trace_id| {
        SpanObservation::checked_native(
            trace_id,
            [0x79; 8],
            None,
            "catalog-bound".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x7a; 32], Vec::new())?,
        )
    };
    let first_trace = [0x7b; 16];
    first_ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&first_authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x7c; 16])?,
                vec![observation(first_trace)?],
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
                StoreBlockIdentity::new([0x7d; 16])?,
                vec![observation(first_trace)?],
            )?
            .into_store_block(),
    )?;
    let first_snapshot = first_ledger.snapshot()?;
    let second_snapshot = second_ledger.snapshot()?;
    assert_eq!(
        first_snapshot.catalog_generation(),
        second_snapshot.catalog_generation()
    );
    assert_ne!(
        first_snapshot.catalog_identity(),
        second_snapshot.catalog_identity()
    );
    let mut maintainer = TraceSummaryMaintainer::new(
        first_authority.governor(),
        scope,
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    let first_maintenance = maintainer.maintain(
        &store,
        &first_snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
    )?;
    let result = store.trace_by_id_with_summary(
        second_authority.governor(),
        tenant,
        &second_snapshot,
        first_trace,
        TraceSearch::all(ScanLimit::new(1)?),
        &first_maintenance,
    )?;
    assert!(matches!(
        result.summary(),
        crate::TraceByIdSummary::Pending(crate::TraceByIdSummaryPending::CatalogMismatch)
    ));
    Ok(())
}
