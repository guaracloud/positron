use super::*;

#[test]
fn compaction_rejects_policy_replacement_between_verification_and_snapshot()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x71; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(13)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x74; 32]));
    let store = LogStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 10)?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x75; 16])?,
                )?,
                vec![record("policy-a-first")?],
            )?
            .into_store_block(),
    )?;
    first.seal()?;
    elapsed.advance(7_000_000_000)?;
    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x76; 16])?,
                )?,
                vec![record("policy-a-second")?],
            )?
            .into_store_block(),
    )?;
    second.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let before = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let first_time = before
        .records()
        .first()
        .ok_or("TOCTOU fixture first record missing")?
        .ingest_time();
    let second_time = before
        .records()
        .get(1)
        .ok_or("TOCTOU fixture second record missing")?
        .ingest_time();
    let bucket = policy.bucket(tenant, first_time)?;
    assert_eq!(bucket, policy.bucket(tenant, second_time)?);
    let replacement_policy = retention_replacement(
        &catalog,
        instance,
        tenant,
        1,
        TransactionId::new([0x77; 16])?,
    )?;
    let cancellation = ReplacePolicyOnFirstCancellation {
        catalog: &catalog,
        expected: Mutex::new(Some(replacement_policy.0)),
        proposal: Mutex::new(Some(replacement_policy.1)),
        committed: AtomicBool::new(false),
        replace_on_cancellation: true,
        replace_on_scan: false,
    };
    let prior_catalog = catalog.pin()?.identity();
    let before_segments = active
        .snapshot()?
        .blocks()
        .iter()
        .map(|block| block.segment_id())
        .collect::<Vec<_>>();
    let governor_before = authority.governor().inspect()?;
    let failure = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &cancellation,
            &NeverCancelledRetention,
        )
        .expect_err("a policy replacement after verification must refuse compaction");
    assert!(
        cancellation
            .committed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::StaleGeneration
    );
    assert_ne!(catalog.pin()?.identity(), prior_catalog);
    assert_eq!(
        active
            .snapshot()?
            .blocks()
            .iter()
            .map(|block| block.segment_id())
            .collect::<Vec<_>>(),
        before_segments
    );
    let governor_after = authority.governor().inspect()?;
    assert_eq!(
        governor_after.outstanding_total(),
        governor_before.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            governor_after.usage(dimension),
            governor_before.usage(dimension)
        );
        assert_eq!(
            governor_after.recovery_shared_usage(dimension),
            governor_before.recovery_shared_usage(dimension)
        );
    }
    let current_policy = LogRetentionPolicy::from_catalog(&catalog.pin()?)?;
    assert_ne!(
        current_policy.bucket(tenant, first_time)?,
        current_policy.bucket(tenant, second_time)?
    );
    drop(before);
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        store
            .scan(
                authority.governor(),
                tenant,
                &reopened.snapshot()?,
                LogScan::all(ScanLimit::new(10)?),
            )?
            .records()
            .len(),
        2
    );
    Ok(())
}

#[test]
fn compaction_allows_unrelated_catalog_churn_with_unchanged_policy_proof()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x78; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x79; 32]), Box::new([0x7a; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(14)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x7b; 32]));
    let store = LogStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 10)?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x7c; 16])?,
                )?,
                vec![record("churn-first")?],
            )?
            .into_store_block(),
    )?;
    first.seal()?;
    elapsed.advance(7_000_000_000)?;
    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x7d; 16])?,
                )?,
                vec![record("churn-second")?],
            )?
            .into_store_block(),
    )?;
    second.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let before = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let bucket = policy.bucket(
        tenant,
        before
            .records()
            .first()
            .ok_or("unchanged-policy fixture first record missing")?
            .ingest_time(),
    )?;
    assert_eq!(
        bucket,
        policy.bucket(
            tenant,
            before
                .records()
                .get(1)
                .ok_or("unchanged-policy fixture second record missing")?
                .ingest_time(),
        )?
    );
    let expected_records = before
        .records()
        .iter()
        .map(|record| record.record().clone())
        .collect::<Vec<_>>();
    let unrelated = unrelated_catalog_update(&catalog, TransactionId::new([0x7e; 16])?)?;
    let churn = ReplacePolicyOnFirstCancellation {
        catalog: &catalog,
        expected: Mutex::new(Some(unrelated.0)),
        proposal: Mutex::new(Some(unrelated.1)),
        committed: AtomicBool::new(false),
        replace_on_cancellation: false,
        replace_on_scan: true,
    };
    let outcome = store.compact_observed(
        &active,
        tenant,
        policy,
        bucket,
        &NeverCancelledRetention,
        &churn,
    )?;
    assert!(churn.committed.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(outcome.input_segments(), 2);
    assert_eq!(outcome.output_segments(), 1);
    let after = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    assert_eq!(after.records().len(), 2);
    assert_eq!(
        after
            .records()
            .iter()
            .map(|record| record.record().clone())
            .collect::<Vec<_>>(),
        expected_records
    );
    Ok(())
}

#[test]
fn compaction_rejects_policy_replacement_after_evaluation_before_commit()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x7f; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x80; 32]), Box::new([0x81; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(15)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x82; 32]));
    let store = LogStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 10)?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x83; 16])?,
                )?,
                vec![record("after-evaluation-first")?],
            )?
            .into_store_block(),
    )?;
    first.seal()?;
    elapsed.advance(7_000_000_000)?;
    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x84; 16])?,
                )?,
                vec![record("after-evaluation-second")?],
            )?
            .into_store_block(),
    )?;
    second.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let before = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let bucket = policy.bucket(
        tenant,
        before
            .records()
            .first()
            .ok_or("after-evaluation fixture first record missing")?
            .ingest_time(),
    )?;
    let replacement = retention_replacement(
        &catalog,
        instance,
        tenant,
        1,
        TransactionId::new([0x85; 16])?,
    )?;
    let replacement_hook = ReplacePolicyOnFirstCancellation {
        catalog: &catalog,
        expected: Mutex::new(Some(replacement.0)),
        proposal: Mutex::new(Some(replacement.1)),
        committed: AtomicBool::new(false),
        replace_on_cancellation: false,
        replace_on_scan: true,
    };
    let before_segments = active
        .snapshot()?
        .blocks()
        .iter()
        .map(|block| block.segment_id())
        .collect::<Vec<_>>();
    let failure = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &NeverCancelledRetention,
            &replacement_hook,
        )
        .expect_err("a policy replacement after evaluation must refuse commit");
    assert!(
        replacement_hook
            .committed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::IntegrityCorruption
    );
    assert_eq!(
        active
            .snapshot()?
            .blocks()
            .iter()
            .map(|block| block.segment_id())
            .collect::<Vec<_>>(),
        before_segments
    );
    drop(active);
    let direct_baseline = authority.governor().inspect()?;
    let direct_active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let direct_snapshot = direct_active.snapshot()?;
    let direct_policy = catalog.pin()?.log_retention_policy()?;
    let direct_blocks = direct_snapshot
        .blocks()
        .iter()
        .zip(before.records())
        .map(|(block, record)| {
            CompactionBlock::new(
                scope,
                block.segment_id(),
                block.identity(),
                block.position(),
                block.payload().to_vec(),
                block.content_digest()?,
                record.ingest_time(),
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let direct_preparation =
        direct_active.prepare_compaction_with_policy(&direct_snapshot, direct_policy)?;
    let direct_replacement = retention_replacement(
        &catalog,
        instance,
        tenant,
        2,
        TransactionId::new([0x86; 16])?,
    )?;
    catalog.commit(direct_replacement.0, direct_replacement.1, None)?;
    let direct_failure = direct_active
        .compact_sealed_with_cancellation(direct_blocks, direct_preparation, || false)
        .expect_err("kernel must reject a changed policy after evaluation");
    assert_eq!(
        direct_failure.code(),
        positron_kernel::LedgerFailureCode::StaleGeneration
    );
    drop(direct_snapshot);
    drop(direct_active);
    let direct_after = authority.governor().inspect()?;
    assert_eq!(
        direct_after.outstanding_total(),
        direct_baseline.outstanding_total()
    );
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        store
            .scan(
                authority.governor(),
                tenant,
                &reopened.snapshot()?,
                LogScan::all(ScanLimit::new(10)?),
            )?
            .records()
            .len(),
        2
    );
    Ok(())
}

#[test]
fn compaction_rejects_a_stale_retention_policy_before_scanning() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0xf6; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xf7; 32]), Box::new([0xf8; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(4)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf9; 32])),
    )?;
    let policy = retention_policy(&catalog, &ledger, tenant, 3_600)?;
    let store = LogStore::new();
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xfa; 16])?,
                )?,
                vec![record("stale policy")?],
            )?
            .into_store_block(),
    )?;
    let scan = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let bucket = policy.bucket(
        tenant,
        scan.records()
            .first()
            .ok_or("stale policy fixture record missing")?
            .ingest_time(),
    )?;
    let basis = catalog.pin()?;
    let objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?.to_vec();
            (!bytes.starts_with(b"POSGOV")).then(|| CatalogObject::new(bytes).ok())?
        })
        .collect::<Vec<_>>();
    let mut objects = objects;
    objects.push(CatalogObject::new(
        super::retention_contract::governance_fixture(instance.to_bytes(), tenant, 2)?,
    )?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xfb; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let generation = catalog.pin()?.identity();
    let failure = store
        .compact(&ledger, tenant, policy, bucket)
        .expect_err("a replaced governance payload invalidates compaction policy");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::IntegrityCorruption
    );
    assert_eq!(catalog.pin()?.identity(), generation);
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    Ok(())
}
