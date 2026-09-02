use super::*;

#[test]
fn compaction_preserves_logical_records_positions_and_snapshot_visibility()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0xd1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xd5; 32]));
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 3_600)?;
    let store = LogStore::new();
    let first_record = record("first")?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xd6; 16])?,
                )?,
                vec![first_record.clone()],
            )?
            .into_store_block(),
    )?;
    let first_sealed = first.seal()?;

    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_record = record("second")?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xd7; 16])?,
                )?,
                vec![second_record.clone()],
            )?
            .into_store_block(),
    )?;
    let second_sealed = second.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let retention_evaluation = active.begin_retention()?;
    assert_eq!(retention_evaluation.blocks().len(), 2);
    drop(retention_evaluation);
    let active_record = record("active")?;
    active.append(
        store
            .prepare(
                active.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xd8; 16])?,
                )?,
                vec![active_record.clone()],
            )?
            .into_store_block(),
    )?;
    let before = active.snapshot()?;
    let before_scan = store.scan(
        authority.governor(),
        tenant,
        &before,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let bucket = policy.bucket(tenant, before_scan.records()[0].ingest_time())?;
    let old_positions = before_scan
        .records()
        .iter()
        .map(|record| (record.commit_position(), record.record_ordinal()))
        .collect::<Vec<_>>();

    let generation_before_scope_refusal = catalog.pin()?.identity();
    let scope_failure = store
        .compact(&active, TenantId::from_bytes([0x42; 16])?, policy, bucket)
        .expect_err("compaction must reject a foreign tenant before publication");
    assert_eq!(
        scope_failure.code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );
    assert_eq!(catalog.pin()?.identity(), generation_before_scope_refusal);

    let cancelled = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &CancelledRetention,
            &NeverCancelledRetention,
        )
        .expect_err("cancelled compaction must not publish output");
    assert_eq!(
        cancelled.code(),
        positron_signals::LogStoreFailureCode::Cancelled
    );
    let observed_failure = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &NeverCancelledRetention,
            &RejectScannedBytes(ScanObservationFailureCode::BudgetExhausted),
        )
        .expect_err("bounded work refusal must not publish output");
    assert_eq!(
        observed_failure.code(),
        positron_signals::LogStoreFailureCode::BudgetExhausted
    );

    let governor_before = authority.governor().inspect()?;
    let emergency_memory = governor_before
        .ordinary_capacity(ResourceDimension::MemoryBytes)
        .checked_sub(governor_before.usage(ResourceDimension::MemoryBytes))
        .and_then(|available| available.checked_sub(1))
        .ok_or("compaction admission fixture has no tenant memory")?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(
            ResourceDimension::MemoryBytes,
            emergency_memory
                .checked_sub(1)
                .ok_or("compaction admission fixture has no blocking capacity")?,
        )?,
    )?)?;
    let admission_generation = catalog.pin()?.identity();
    let admission_failure = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &NeverCancelledRetention,
            &RejectScannedBytes(ScanObservationFailureCode::BudgetExhausted),
        )
        .expect_err("copy-on-write admission must precede Log Store payload scanning");
    assert_eq!(
        admission_failure.code(),
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(catalog.pin()?.identity(), admission_generation);
    drop(blocker);
    let governor_after = authority.governor().inspect()?;
    assert_eq!(
        governor_after.outstanding_total(),
        governor_before.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            governor_after.recovery_shared_usage(dimension),
            governor_before.recovery_shared_usage(dimension)
        );
    }
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            governor_after.usage(dimension),
            governor_before.usage(dimension)
        );
        assert_eq!(
            governor_after.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension),
            governor_before.recovery_pool_usage(RecoveryWorkKind::EmergencyCompaction, dimension)
        );
    }

    let prior_generation = catalog.pin()?.identity();
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            store.compact(&active, tenant, policy, bucket)
        })
        .expect_err("a failed catalog publication must not report compaction");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::StorageUnavailable
    );
    assert_eq!(catalog.pin()?.identity(), prior_generation);
    assert_eq!(
        store
            .scan(
                authority.governor(),
                tenant,
                &active.snapshot()?,
                LogScan::all(ScanLimit::new(10)?),
            )?
            .records()
            .len(),
        3
    );

    let outcome = with_catalog_publication_ambiguity_hook_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        |_| {},
        || store.compact(&active, tenant, policy, bucket),
    )?;
    assert_eq!(outcome.bucket(), bucket);
    assert_eq!(outcome.input_segments(), 2);
    assert_eq!(outcome.output_segments(), 1);
    assert_eq!(outcome.input_blocks(), 2);
    let repeated = store.compact(&active, tenant, policy, bucket)?;
    assert_eq!(repeated.input_segments(), 0);
    assert_eq!(repeated.output_segments(), 0);

    let after_scan = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    assert_eq!(
        after_scan
            .records()
            .iter()
            .map(|record| record.record().body())
            .collect::<Vec<_>>(),
        vec![
            first_record.body(),
            second_record.body(),
            active_record.body(),
        ]
    );
    assert_eq!(
        after_scan
            .records()
            .iter()
            .map(|record| (record.commit_position(), record.record_ordinal()))
            .collect::<Vec<_>>(),
        old_positions
    );
    assert_eq!(
        store
            .scan(
                authority.governor(),
                tenant,
                &before,
                LogScan::all(ScanLimit::new(10)?),
            )?
            .records()
            .len(),
        3
    );
    assert_eq!(first_sealed.frontier().value(), 1);
    assert_eq!(second_sealed.frontier().value(), 2);
    drop(before);
    drop(after_scan);
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    assert_eq!(restarted.records().len(), 3);
    assert_eq!(restarted.records()[0].commit_position().value(), 1);
    assert_eq!(restarted.records()[1].commit_position().value(), 2);
    assert_eq!(restarted.records()[2].commit_position().value(), 3);
    Ok(())
}

#[test]
fn compaction_with_only_an_active_segment_is_an_empty_noop() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xf1; 16])?,
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(3)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf4; 32])),
    )?;
    let policy = retention_policy(&catalog, &ledger, tenant, 3_600)?;
    let store = LogStore::new();
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xf5; 16])?,
                )?,
                vec![record("active only")?],
            )?
            .into_store_block(),
    )?;
    let scan = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let bucket = policy.bucket(tenant, scan.records()[0].ingest_time())?;
    let outcome = store.compact(&ledger, tenant, policy, bucket)?;
    assert_eq!(outcome.bucket(), bucket);
    assert_eq!(outcome.input_segments(), 0);
    assert_eq!(outcome.output_segments(), 0);
    assert_eq!(outcome.input_blocks(), 0);

    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf4; 32])),
    )?;
    let sealed_scan = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let sealed_bucket = policy.bucket(
        tenant,
        sealed_scan
            .records()
            .first()
            .ok_or("sealed no-op fixture record missing")?
            .ingest_time(),
    )?;
    let sealed_outcome = store.compact(&reopened, tenant, policy, sealed_bucket)?;
    assert_eq!(sealed_outcome.input_segments(), 0);
    assert_eq!(sealed_outcome.output_segments(), 0);
    assert_eq!(sealed_outcome.input_blocks(), 0);
    Ok(())
}
