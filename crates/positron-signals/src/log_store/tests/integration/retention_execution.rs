use super::*;

#[test]
fn public_log_store_commits_and_scans_through_the_storage_kernel() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(8)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("public outcome".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "duplicate".to_owned(),
            vec![
                CandidateAttributeValue::string("first".to_owned()),
                CandidateAttributeValue::string("second".to_owned()),
            ],
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected the public fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x68; 16])?,
    )?;
    let authoritative_ingest_time = preparation.ingest_time();
    ledger.append(
        store
            .prepare(preparation, vec![record.clone()])?
            .into_store_block(),
    )?;

    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records()[0].record(), &record);
    assert_eq!(result.records()[0].ingest_time(), authoritative_ingest_time);
    assert!(result.complete());
    Ok(())
}

#[test]
fn restart_preserves_each_block_ingest_time_and_uses_the_segment_max_for_retention()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1c; 16])?,
        CatalogSecret::from_owned(Box::new([0x2c; 32]), Box::new([0x3c; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(12)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            None,
            None,
            Some(CandidateAttributeValue::string(
                "distinct durable ingest times".to_owned(),
            )),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the restart fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )?;
    let first = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x6c; 16])?,
    )?;
    let first_ingest_time = first.ingest_time();
    ledger.append(
        store
            .prepare(first, vec![record.clone()])?
            .into_store_block(),
    )?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let second = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x7c; 16])?,
    )?;
    let second_ingest_time = second.ingest_time();
    assert!(second_ingest_time > first_ingest_time);
    ledger.append(store.prepare(second, vec![record])?.into_store_block())?;
    ledger.seal()?;

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )?;
    let scanned = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(2)?),
    )?;
    assert_eq!(scanned.records().len(), 2);
    assert_eq!(scanned.records()[0].ingest_time(), first_ingest_time);
    assert_eq!(scanned.records()[1].ingest_time(), second_ingest_time);
    let policy = retention_policy(&catalog, &reopened, tenant, 1)?;
    let still_fresh = store.enforce_retention(&reopened, tenant, policy)?;
    assert_eq!(still_fresh.expired_segments(), 0);
    assert_eq!(reopened.snapshot()?.blocks().len(), 2);

    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let expired = store.enforce_retention(&reopened, tenant, policy)?;
    assert_eq!(expired.expired_segments(), 1);
    assert!(reopened.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn expired_sealed_logs_are_removed_by_kernel_ingest_time_only() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(9)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            Some(i64::MAX),
            None,
            Some(CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "native".to_owned(),
                    CandidateAttributeValue::array(vec![
                        CandidateAttributeValue::null(),
                        CandidateAttributeValue::boolean(true),
                        CandidateAttributeValue::signed_integer(-7),
                        CandidateAttributeValue::floating_point_bits(3.5_f64.to_bits()),
                        CandidateAttributeValue::string(
                            "producer time cannot retain this record".to_owned(),
                        ),
                        CandidateAttributeValue::bytes(vec![0, 1, 2]),
                    ]),
                ),
            ])),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the retention fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x69; 16])?,
                )?,
                vec![record.clone(), record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x79; 16])?,
                )?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    active.append(
        store
            .prepare(
                active.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x89; 16])?,
                )?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    for (observation, expected) in [
        (
            ScanObservationFailureCode::BudgetExhausted,
            positron_signals::LogStoreFailureCode::BudgetExhausted,
        ),
        (
            ScanObservationFailureCode::DecodedRecordsExhausted,
            positron_signals::LogStoreFailureCode::LimitExceeded,
        ),
        (
            ScanObservationFailureCode::ResourceExhausted,
            positron_signals::LogStoreFailureCode::ResourceExhausted,
        ),
        (
            ScanObservationFailureCode::Internal,
            positron_signals::LogStoreFailureCode::Internal,
        ),
    ] {
        let failure = store
            .enforce_retention_observed(
                &active,
                tenant,
                retention_policy(&catalog, &active, tenant, 1)?,
                &NeverCancelledRetention,
                &RejectScannedBytes(observation),
            )
            .expect_err("observer refusal must precede retention publication");
        assert_eq!(failure.code(), expected);
        assert_eq!(active.snapshot()?.blocks().len(), 3);
    }

    let recovery_baseline = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::DurabilityRecovery);
    let recovery_claim = RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::new([1; 11]),
    )?;
    let mut held_recovery = Vec::new();
    while let Ok(reservation) = authority.recovery().reserve(recovery_claim) {
        held_recovery.push(reservation);
    }
    assert!(!held_recovery.is_empty());
    let public_refusal = store
        .enforce_retention(
            &active,
            tenant,
            retention_policy(&catalog, &active, tenant, 1)?,
        )
        .expect_err("public retention must preserve kernel recovery refusal");
    assert_eq!(
        public_refusal.code(),
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(active.snapshot()?.blocks().len(), 3);
    drop(held_recovery);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::DurabilityRecovery),
        recovery_baseline
    );
    assert_eq!(active.snapshot()?.blocks().len(), 3);

    let outcome = store.enforce_retention(
        &active,
        tenant,
        retention_policy(&catalog, &active, tenant, 1)?,
    )?;
    assert!(outcome.evaluated_at().value() > 0);
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 1);
    assert_eq!(
        outcome.clock_provenance(),
        positron_kernel::RetentionCutoffProvenance::PersistedRetentionFrontier
    );
    let result = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records().len(), 1);
    assert_eq!(result.records()[0].record(), &record);
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records().len(), 1);
    assert_eq!(result.records()[0].record(), &record);
    drop(reopened);
    let reopened_again = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &reopened_again.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records().len(), 1);
    assert_eq!(result.records()[0].record(), &record);
    Ok(())
}
