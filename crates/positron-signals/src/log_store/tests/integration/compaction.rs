use super::*;

fn record(body: &str) -> Result<LogRecord, Box<dyn Error>> {
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string(body.to_owned())),
        vec![],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected the compaction fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        *evaluated,
    )?)
}

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
fn compaction_keeps_sealed_segments_in_other_retention_buckets_untouched()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(1_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xe4; 32]));
    let store = LogStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 2)?;
    let first_preparation = first.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe5; 16])?,
    )?;
    first.append(
        store
            .prepare(first_preparation, vec![record("old bucket")?])?
            .into_store_block(),
    )?;
    first.seal()?;
    elapsed.advance(3_000_000_000)?;
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
                    StoreBlockIdentity::new([0xe6; 16])?,
                )?,
                vec![record("new bucket one")?],
            )?
            .into_store_block(),
    )?;
    second.seal()?;

    let third = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    third.append(
        store
            .prepare(
                third.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xe7; 16])?,
                )?,
                vec![record("new bucket two")?],
            )?
            .into_store_block(),
    )?;
    third.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let snapshot = active.snapshot()?;
    let before = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let old_bucket = policy.bucket(
        tenant,
        before
            .records()
            .first()
            .ok_or("old retention bucket fixture record missing")?
            .ingest_time(),
    )?;
    let target = policy.bucket(
        tenant,
        before
            .records()
            .get(1)
            .ok_or("new retention bucket fixture record missing")?
            .ingest_time(),
    )?;
    assert_ne!(old_bucket, target);
    assert!(before.records().iter().skip(1).all(|record| {
        policy
            .bucket(tenant, record.ingest_time())
            .is_ok_and(|bucket| bucket == target)
    }));
    let outcome = store.compact(&active, tenant, policy, target)?;
    assert_eq!(outcome.input_segments(), 2);
    assert_eq!(outcome.output_segments(), 1);
    let after = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    assert_eq!(after.records().len(), 3);
    assert_eq!(
        after.records()[0].record().body(),
        before.records()[0].record().body()
    );
    drop(snapshot);
    drop(before);
    drop(after);
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
        3
    );
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

#[test]
fn compaction_preserves_every_public_log_semantic_across_restart() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x91; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(6)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0x94; 32]));
    let store = LogStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 3_600)?;
    let mut schema = SchemaSessionStore::new(
        preparation_capacity(&authority, tenant)?,
        tenant,
        SchemaBudget::new(1, 8_192, 512, 256)?,
    )?;
    let identity = StoreBlockIdentity::new([0x95; 16])?;
    let mut first_records = vec![semantic_record(true)?, semantic_absent_record()?];
    let delta = schema.stage_group(&mut first_records)?;
    let first_block = store
        .prepare(
            first.begin_store_block(preparation_capacity(&authority, tenant)?, identity)?,
            first_records,
        )?
        .into_store_block();
    let first_digest = first_block.content_digest()?;
    first.append(first_block)?;
    schema.commit(delta, identity, first_digest)?;
    first.seal()?;

    for (identity_bytes, body_marker) in [([0x96; 16], 2_u8), ([0x97; 16], 3_u8)] {
        let segment = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        let identity = StoreBlockIdentity::new(identity_bytes)?;
        let records = vec![
            semantic_record(body_marker == 2)?,
            semantic_absent_record()?,
        ];
        segment.append(
            store
                .prepare(
                    segment
                        .begin_store_block(preparation_capacity(&authority, tenant)?, identity)?,
                    records,
                )?
                .into_store_block(),
        )?;
        segment.seal()?;
    }

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
    assert_eq!(before.records().len(), 6);
    assert_eq!(
        before.records()[0]
            .attributes()
            .get(1)
            .map(StoredLogAttribute::representation),
        Some(AttributeRepresentation::SchemaOverflow)
    );
    let bucket = policy.bucket(tenant, before.records()[0].ingest_time())?;
    let expected = before
        .records()
        .iter()
        .map(|record| {
            (
                record.record().clone(),
                record.ingest_time(),
                record
                    .attributes()
                    .iter()
                    .map(StoredLogAttribute::representation)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let outcome = store.compact(&active, tenant, policy, bucket)?;
    assert_eq!(outcome.input_segments(), 3);
    assert_eq!(outcome.output_segments(), 1);
    let after = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let actual = after
        .records()
        .iter()
        .map(|record| {
            (
                record.record().clone(),
                record.ingest_time(),
                record
                    .attributes()
                    .iter()
                    .map(StoredLogAttribute::representation)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert_eq!(
        after
            .records()
            .iter()
            .map(|record| record.policy_provenance())
            .collect::<Vec<_>>(),
        before
            .records()
            .iter()
            .map(|record| record.policy_provenance())
            .collect::<Vec<_>>()
    );
    drop(before);
    drop(after);
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
    assert_eq!(
        restarted
            .records()
            .iter()
            .map(|record| record.record().clone())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|(record, _, _)| record.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        restarted.records()[0]
            .attributes()
            .get(1)
            .map(StoredLogAttribute::representation),
        Some(AttributeRepresentation::SchemaOverflow)
    );
    Ok(())
}

fn semantic_record(first_variant: bool) -> Result<LogRecord, Box<dyn Error>> {
    let body = CandidateAttributeValue::array(vec![
        CandidateAttributeValue::null(),
        CandidateAttributeValue::boolean(first_variant),
        CandidateAttributeValue::signed_integer(-7),
        CandidateAttributeValue::floating_point_bits(1.5_f64.to_bits()),
        CandidateAttributeValue::string("typed text".to_owned()),
        CandidateAttributeValue::bytes(vec![0, 1, 2]),
        CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(false)]),
        CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "nested".to_owned(),
                CandidateAttributeValue::signed_integer(9),
            ),
            CandidateKeyValue::new(
                "nested".to_owned(),
                CandidateAttributeValue::string("duplicate".to_owned()),
            ),
        ]),
    ]);
    let attributes = vec![
        NativeLogAttribute::new(
            AttributeNamespace::Record,
            "typed".to_owned(),
            vec![
                CandidateAttributeValue::signed_integer(1),
                CandidateAttributeValue::signed_integer(1),
            ],
        ),
        NativeLogAttribute::new(
            AttributeNamespace::Record,
            "overflow".to_owned(),
            vec![CandidateAttributeValue::string("fallback".to_owned())],
        ),
    ];
    let metadata = LogMetadata::new_with_event_name(
        7,
        "WARN".to_owned(),
        "semantic".to_owned(),
        Some([0x11; 16]),
        Some([0x12; 8]),
        3,
        4,
        5,
        "https://resource".to_owned(),
        "scope".to_owned(),
        "1.0".to_owned(),
        6,
        "https://scope".to_owned(),
    );
    let candidate = NativeLogCandidate::new(Some(-4), Some(0), Some(body), attributes, metadata);
    let PolicyEvaluation::Accepted(evaluated) =
        semantic_policy()?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("semantic policy rejected the typed fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        *evaluated,
    )?)
}

fn semantic_absent_record() -> Result<LogRecord, Box<dyn Error>> {
    let candidate = NativeLogCandidate::new(None, None, None, Vec::new(), LogMetadata::empty());
    let PolicyEvaluation::Accepted(evaluated) =
        semantic_policy()?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("semantic policy rejected the absent fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        *evaluated,
    )?)
}

fn semantic_policy() -> Result<IngestPolicy, Box<dyn Error>> {
    Ok(IngestPolicy::compile(
        7,
        vec![
            PolicyRule::new(
                "rule-a",
                vec![PolicyPredicate::Receiver(PolicyReceiver::OtlpGrpc)],
                PolicyAction::Accept,
            )?,
            PolicyRule::new(
                "rule-a-duplicate",
                vec![PolicyPredicate::Receiver(PolicyReceiver::OtlpGrpc)],
                PolicyAction::Accept,
            )?,
            PolicyRule::new(
                "rule-b",
                vec![PolicyPredicate::Receiver(PolicyReceiver::OtlpGrpc)],
                PolicyAction::Accept,
            )?,
        ],
    )?)
}
