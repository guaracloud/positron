use super::*;

#[test]
fn native_trace_compaction_preserves_manifest_snapshots_and_restart_visibility()
-> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let authority = authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0x71; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    install_trace_retention(&catalog, instance, tenant, 3_600)?;
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(9)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x74; 32]));
    let store = TraceStore::new();
    for (identity, span, name) in [
        ([0x75; 16], [0x76; 8], "first"),
        ([0x77; 16], [0x78; 8], "second"),
    ] {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention,
            &catalog,
            scope,
            key(),
        )?;
        ledger.append(
            store
                .prepare(
                    ledger.begin_store_block(
                        preparation_capacity(&authority, tenant)?,
                        positron_kernel::StoreBlockIdentity::new(identity)?,
                    )?,
                    vec![trace_observation(span, name)?],
                )?
                .into_store_block(),
        )?;
        ledger.seal()?;
    }
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let pinned = active.snapshot()?;
    let before = store.scan_physical(
        authority.governor(),
        tenant,
        &pinned,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    let expected = before
        .observations()
        .iter()
        .map(|span| {
            (
                span.observation().span_id(),
                span.observation().name().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let policy = TraceRetentionPolicy::from_catalog(&catalog.pin()?)?;
    let bucket = policy.bucket(
        tenant,
        before
            .observations()
            .first()
            .ok_or("trace fixture empty")?
            .stored()
            .ingest_time(),
    )?;
    let generation_before_failures = catalog.pin()?.identity();
    let foreign_tenant = TenantId::from_bytes([0x85; 16])?;
    let scope_failure = store
        .compact(&active, foreign_tenant, policy, bucket)
        .expect_err("foreign tenant must be rejected before Trace publication");
    assert_eq!(
        scope_failure.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    assert_eq!(catalog.pin()?.identity(), generation_before_failures);
    let cancelled = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &AlwaysCancelled,
            &Unobserved,
        )
        .expect_err("cancelled Trace compaction must preserve the prior manifest");
    assert_eq!(cancelled.code(), TraceStoreFailureCode::Cancelled);
    assert_eq!(catalog.pin()?.identity(), generation_before_failures);
    let publication_failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            store.compact(&active, tenant, policy, bucket)
        })
        .expect_err("publication failure must preserve the prior Trace manifest");
    assert_eq!(
        publication_failure.code(),
        TraceStoreFailureCode::StorageUnavailable
    );
    assert_eq!(catalog.pin()?.identity(), generation_before_failures);
    let outcome = store.compact(&active, tenant, policy, bucket)?;
    assert_eq!(
        (outcome.input_segments(), outcome.output_segments()),
        (2, 1)
    );
    let after = store.scan_physical(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(
        after
            .observations()
            .iter()
            .map(|span| (
                span.observation().span_id(),
                span.observation().name().to_owned()
            ))
            .collect::<Vec<_>>(),
        expected
    );
    let pinned_after = store.scan_physical(
        authority.governor(),
        tenant,
        &pinned,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(
        pinned_after
            .observations()
            .iter()
            .map(|span| (
                span.observation().span_id(),
                span.observation().name().to_owned()
            ))
            .collect::<Vec<_>>(),
        expected
    );
    drop(pinned_after);
    drop(after);
    drop(before);
    drop(pinned);
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let restarted = store.scan_physical(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(
        restarted
            .observations()
            .iter()
            .map(|span| (
                span.observation().span_id(),
                span.observation().name().to_owned()
            ))
            .collect::<Vec<_>>(),
        expected
    );
    Ok(())
}

struct AlwaysCancelled;

impl ScanCancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct Unobserved;

impl ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

#[test]
fn public_trace_store_retention_uses_kernel_ingest_time() -> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let authority = authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0x91; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    install_trace_retention(&catalog, instance, tenant, 1)?;
    let (retention, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(10)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x94; 32]));
    let store = TraceStore::new();
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    sealed.append(
        store
            .prepare(
                sealed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0x95; 16])?,
                )?,
                vec![trace_observation([0x96; 8], "expired")?],
            )?
            .into_store_block(),
    )?;
    sealed.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let pinned = active.snapshot()?;
    let outcome = store.enforce_retention(
        &active,
        tenant,
        TraceRetentionPolicy::from_catalog(&catalog.pin()?)?,
    )?;
    assert_eq!(outcome.expired_segments(), 1);
    assert!(active.snapshot()?.blocks().is_empty());
    let pinned_scan = store.scan_physical(
        authority.governor(),
        tenant,
        &pinned,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(pinned_scan.observations().len(), 1);
    assert_eq!(
        pinned_scan.observations()[0].observation().name(),
        "expired"
    );
    let identity = catalog.pin()?.identity();
    let cancelled = store
        .enforce_retention_observed(
            &active,
            tenant,
            TraceRetentionPolicy::from_catalog(&catalog.pin()?)?,
            &CancelAfterInitialPoll::new(),
            &Unobserved,
        )
        .expect_err("late cancellation must prevent an empty retention publication");
    assert_eq!(cancelled.code(), TraceStoreFailureCode::Cancelled);
    assert_eq!(catalog.pin()?.identity(), identity);
    Ok(())
}

#[test]
fn public_trace_store_compaction_skips_mixed_fixed_buckets() -> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let authority = authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xa1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    install_trace_retention(&catalog, instance, tenant, 2)?;
    let (retention, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(1_000_000_000));
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(12)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0xa5; 32]));
    let store = TraceStore::new();
    let policy = TraceRetentionPolicy::from_catalog(&catalog.pin()?)?;
    let mixed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    mixed.append(
        store
            .prepare(
                mixed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0xa6; 16])?,
                )?,
                vec![trace_observation([0xa7; 8], "mixed-old")?],
            )?
            .into_store_block(),
    )?;
    elapsed.advance(3_000_000_000)?;
    mixed.append(
        store
            .prepare(
                mixed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0xa8; 16])?,
                )?,
                vec![trace_observation([0xa9; 8], "mixed-target")?],
            )?
            .into_store_block(),
    )?;
    let mixed_segment = mixed.seal()?.segment_id();
    for (identity, span, name) in [
        ([0xaa; 16], [0xab; 8], "complete-target-one"),
        ([0xac; 16], [0xad; 8], "complete-target-two"),
    ] {
        let sealed = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention,
            &catalog,
            scope,
            key(),
        )?;
        sealed.append(
            store
                .prepare(
                    sealed.begin_store_block(
                        preparation_capacity(&authority, tenant)?,
                        positron_kernel::StoreBlockIdentity::new(identity)?,
                    )?,
                    vec![trace_observation(span, name)?],
                )?
                .into_store_block(),
        )?;
        sealed.seal()?;
    }
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let before = active.snapshot()?;
    let before_scan = store.scan_physical(
        authority.governor(),
        tenant,
        &before,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    let expected = before_scan
        .observations()
        .iter()
        .map(|span| {
            (
                span.observation().span_id(),
                span.observation().name().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let bucket = policy.bucket(
        tenant,
        before_scan
            .observations()
            .get(1)
            .ok_or("mixed bucket target span missing")?
            .stored()
            .ingest_time(),
    )?;
    drop(before_scan);
    drop(before);
    let outcome = store.compact(&active, tenant, policy, bucket)?;
    assert_eq!(
        (outcome.input_segments(), outcome.output_segments()),
        (2, 1)
    );
    let after = active.snapshot()?;
    assert_eq!(
        after
            .blocks()
            .iter()
            .filter(|block| block.segment_id() == mixed_segment)
            .count(),
        2
    );
    let after_scan = store.scan_physical(
        authority.governor(),
        tenant,
        &after,
        TraceScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(
        after_scan
            .observations()
            .iter()
            .map(|span| (
                span.observation().span_id(),
                span.observation().name().to_owned()
            ))
            .collect::<Vec<_>>(),
        expected
    );
    Ok(())
}

#[test]
fn native_trace_compaction_preserves_conflicts_and_reopens_summary_for_late_data()
-> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let authority = authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xb1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    install_trace_retention(&catalog, instance, tenant, 3_600)?;
    let (retention, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(13)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0xb4; 32]));
    let store = TraceStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let original = trace_observation([0xb5; 8], "original")?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0xb6; 16])?,
                )?,
                vec![
                    original.clone(),
                    original,
                    trace_observation([0xb5; 8], "conflicting-variant")?,
                ],
            )?
            .into_store_block(),
    )?;
    first.seal()?;
    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0xb7; 16])?,
                )?,
                vec![trace_observation([0xb8; 8], "successor")?],
            )?
            .into_store_block(),
    )?;
    second.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let before = active.snapshot()?;
    let before_logical = store.scan(
        authority.governor(),
        tenant,
        &before,
        TraceScan::all(ScanLimit::new(16)?),
    )?;
    let expected = before_logical
        .spans()
        .iter()
        .map(|span| {
            (
                span.span_id(),
                span.observation_count(),
                span.variants().len(),
                span.conflicted(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        expected,
        vec![([0xb5; 8], 3, 2, true), ([0xb8; 8], 1, 1, false)]
    );
    let policy = TraceRetentionPolicy::from_catalog(&catalog.pin()?)?;
    let first_ingest_time = before_logical
        .spans()
        .first()
        .and_then(|span| span.variants().first())
        .ok_or("missing initial trace variant")?
        .observation()
        .ingest_time();
    drop(before_logical);
    let outcome = store.compact(
        &active,
        tenant,
        policy,
        policy.bucket(tenant, first_ingest_time)?,
    )?;
    assert_eq!(
        (outcome.input_segments(), outcome.output_segments()),
        (2, 1)
    );
    let compacted = active.snapshot()?;
    let compacted_logical = store.scan(
        authority.governor(),
        tenant,
        &compacted,
        TraceScan::all(ScanLimit::new(16)?),
    )?;
    assert_eq!(
        compacted_logical
            .spans()
            .iter()
            .map(|span| (
                span.span_id(),
                span.observation_count(),
                span.variants().len(),
                span.conflicted(),
            ))
            .collect::<Vec<_>>(),
        expected
    );
    drop(compacted_logical);
    let mut summaries = TraceSummaryMaintainer::new(
        authority.governor(),
        scope,
        TraceQuietPeriod::new(1)?,
        ScanLimit::new(16)?,
    )?;
    {
        let completed = summaries.maintain(
            &store,
            &compacted,
            &NeverCancelled,
            &Unobserved,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(200))),
        )?;
        let summary = completed
            .summary([0x79; 16])
            .ok_or("summary missing after compaction")?;
        assert_eq!(summary.observation_count(), 4);
        assert_eq!(summary.logical_span_count(), 2);
        assert_eq!(summary.conflicted_span_count(), 1);
        assert!(summary.quiescent());
    }
    elapsed.advance(101)?;
    active.append(
        store
            .prepare(
                active.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0xb9; 16])?,
                )?,
                vec![trace_observation([0xba; 8], "late")?],
            )?
            .into_store_block(),
    )?;
    let reopened = summaries.maintain(
        &store,
        &active.snapshot()?,
        &NeverCancelled,
        &Unobserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(201))),
    )?;
    let reopened_summary = reopened
        .summary([0x79; 16])
        .ok_or("reopened summary missing")?;
    assert_eq!(reopened.applied_observations(), 1);
    assert_eq!(reopened_summary.observation_count(), 5);
    assert_eq!(reopened_summary.logical_span_count(), 3);
    assert_eq!(reopened_summary.conflicted_span_count(), 1);
    assert!(!reopened_summary.quiescent());
    Ok(())
}

#[test]
fn public_trace_store_compaction_rejects_corrupt_sealed_blocks_before_publication()
-> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let authority = authority(PrimaryDataVolume::acquire(
        root.path(),
        MountQualification::LocalHost,
    )?)?;
    let instance = InstanceId::new([0xc1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    install_trace_retention(&catalog, instance, tenant, 3_600)?;
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(14)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0xc4; 32]));
    let store = TraceStore::new();
    let policy = TraceRetentionPolicy::from_catalog(&catalog.pin()?)?;
    let corrupt = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let preparation = corrupt.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        positron_kernel::StoreBlockIdentity::new([0xc5; 16])?,
    )?;
    let bucket = policy.bucket(tenant, preparation.ingest_time())?;
    let mut invalid_bytes = legacy_v1_block(tenant, preparation.ingest_time().instant().value());
    let first = invalid_bytes
        .first_mut()
        .ok_or("legacy corruption fixture unexpectedly empty")?;
    *first ^= 0xff;
    corrupt.append(preparation.finish(invalid_bytes)?)?;
    corrupt.seal()?;
    let valid = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    valid.append(
        store
            .prepare(
                valid.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    positron_kernel::StoreBlockIdentity::new([0xc6; 16])?,
                )?,
                vec![trace_observation([0xc7; 8], "valid")?],
            )?
            .into_store_block(),
    )?;
    valid.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        key(),
    )?;
    let before_identity = catalog.pin()?.identity();
    let before_blocks = active.snapshot()?.blocks().len();
    let failure = store
        .compact(&active, tenant, policy, bucket)
        .expect_err("corrupt sealed Trace block must not publish a compacted manifest");
    assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    assert_eq!(catalog.pin()?.identity(), before_identity);
    assert_eq!(active.snapshot()?.blocks().len(), before_blocks);
    Ok(())
}
