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
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                VirtualShardId::new(8)?,
                StoreBlockIdentity::new([0x68; 16])?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;

    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records()[0].record(), &record);
    assert!(result.complete());
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
    let ingest_clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        10_000_000_000,
    )));
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &ingest_clock,
                tenant,
                shard,
                StoreBlockIdentity::new([0x69; 16])?,
                vec![record.clone(), record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &ingest_clock,
                tenant,
                shard,
                StoreBlockIdentity::new([0x79; 16])?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;

    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            12_000_000_000,
        ))),
    )?;
    active.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                    i64::MAX / 2,
                ))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x89; 16])?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    let duration = NonZeroU64::new(1).ok_or("positive retention duration")?;
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
                &retention_clock(),
                tenant,
                LogRetentionPolicy::new(1)?,
                &NeverCancelledRetention,
                &RejectScannedBytes(observation),
            )
            .expect_err("observer refusal must precede retention publication");
        assert_eq!(failure.code(), expected);
        assert_eq!(active.snapshot()?.blocks().len(), 3);
    }

    let evidence_snapshot = active.snapshot()?;
    let evidence_block = evidence_snapshot
        .blocks()
        .first()
        .ok_or("sealed retention fixture is missing its committed block")?;
    let evidence = evidence_snapshot.retention_evidence(
        evidence_block,
        NonZeroU64::new(1).ok_or("positive retention duration")?,
    )?;
    let cutoff = retention_clock().retention_cutoff(duration)?;
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
            &retention_clock(),
            tenant,
            LogRetentionPolicy::new(1)?,
        )
        .expect_err("public retention must preserve kernel recovery refusal");
    assert_eq!(
        public_refusal.code(),
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused
    );
    let refused = active
        .retire_expired_sealed_segments(cutoff, &[evidence])
        .expect_err("saturated retention recovery capacity must fail before publication");
    assert_eq!(
        refused.code(),
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(evidence_snapshot.blocks().len(), 3);
    drop(held_recovery);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::DurabilityRecovery),
        recovery_baseline
    );
    let incomplete = active.retire_expired_sealed_segments(cutoff, &[])?;
    assert_eq!(incomplete.logically_retired_segments(), 0);
    assert_eq!(active.snapshot()?.blocks().len(), 3);
    let excessive = vec![evidence; 1_025];
    let bounded = active
        .retire_expired_sealed_segments(cutoff, &excessive)
        .expect_err("retention evidence must remain bounded");
    assert_eq!(
        bounded.code(),
        positron_kernel::LedgerFailureCode::LimitExceeded
    );
    let duplicate = active
        .retire_expired_sealed_segments(cutoff, &[evidence, evidence])
        .expect_err("duplicate block evidence must fail before publication");
    assert_eq!(
        duplicate.code(),
        positron_kernel::LedgerFailureCode::InvalidInput
    );
    assert_eq!(active.snapshot()?.blocks().len(), 3);
    drop(evidence_snapshot);

    let outcome = store.enforce_retention(
        &active,
        &retention_clock(),
        tenant,
        LogRetentionPolicy::new(1)?,
    )?;
    assert!(outcome.evaluated_at().value() > 12_000_000_000);
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 1);
    assert_eq!(
        outcome.clock_provenance(),
        positron_kernel::RetentionCutoffProvenance::LifecycleClock
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
