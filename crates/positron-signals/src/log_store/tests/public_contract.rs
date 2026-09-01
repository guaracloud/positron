use super::*;

#[test]
fn public_limits_and_failures_are_typed_and_redacted() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    assert_eq!(
        ScanLimit::new(0)
            .expect_err("unbounded empty scan limit is invalid")
            .code(),
        LogStoreFailureCode::LimitExceeded
    );
    assert_eq!(
        ScanLimit::new(1_025)
            .expect_err("scan limit exceeds the M1 result bound")
            .code(),
        LogStoreFailureCode::LimitExceeded
    );

    let policy = PolicyProvenance::new(1, [0x70; 32], vec![])?;
    let zero_time = LogRecord::checked_minimal(
        Some(0),
        None,
        vec![("scope", "name", "value")],
        policy.clone(),
    )?;
    let positive_time = LogRecord::checked_minimal(
        Some(11),
        None,
        vec![("instrumentation-scope", "name", "value")],
        policy.clone(),
    )?;
    assert_eq!(zero_time.event_time().quality(), SourceTimeQuality::Zero);
    assert_eq!(
        positive_time.event_time().quality(),
        SourceTimeQuality::Usable
    );
    assert_eq!(zero_time.body(), None);
    assert_eq!(
        LogRecord::checked_minimal(
            None,
            None,
            vec![("unknown", "key", "value")],
            policy.clone(),
        )
        .expect_err("only native namespaces are accepted")
        .code(),
        LogStoreFailureCode::InvalidInput
    );

    let profile = value_profile()?;
    let attribute = StoredLogAttribute::generic(occurrences(
        profile,
        AttributeNamespace::Record,
        "bounded",
        vec![CandidateAttributeValue::boolean(true)],
    )?);
    let too_many_attributes = vec![attribute; 1_025];
    assert_eq!(
        LogRecord::checked_native(
            profile,
            EventTime::missing(),
            None,
            None,
            too_many_attributes,
            LogMetadata::empty(),
            policy.clone(),
        )
        .expect_err("record attribute sets are bounded")
        .code(),
        LogStoreFailureCode::LimitExceeded
    );

    let tenant = TenantId::from_bytes([0x41; 16])?;
    let store = LogStore::new();
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let retention_time = positron_kernel::RetentionTimeAuthority::establish()?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(8)?);
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x64; 32])),
    )?;
    let baseline = authority.governor().inspect()?.outstanding_total();
    let empty_failure = match store.prepare(
        ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new([0x65; 16])?,
        )?,
        vec![],
    ) {
        Ok(_) => return Err("kernel-authorized empty Log block was accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(empty_failure.code(), LogStoreFailureCode::InvalidInput);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline
    );

    let empty_failure = store
        .prepare_unretained_for_test(
            preparation_capacity(&authority, tenant)?,
            &clock(1),
            tenant,
            VirtualShardId::new(9)?,
            StoreBlockIdentity::new([0x69; 16])?,
            vec![],
        )
        .err()
        .ok_or("an empty canonical block unexpectedly prepared")?;
    assert_eq!(empty_failure.code(), LogStoreFailureCode::LimitExceeded);
    let large_record = LogRecord::checked_minimal(None, Some("x".repeat(262_144)), vec![], policy)?;
    let block_bound = store
        .prepare_unretained_for_test(
            preparation_capacity(&authority, tenant)?,
            &clock(1),
            tenant,
            VirtualShardId::new(10)?,
            StoreBlockIdentity::new([0x6a; 16])?,
            vec![large_record; 5],
        )
        .err()
        .ok_or("an oversized canonical Store Block unexpectedly prepared")?;
    assert_eq!(block_bound.code(), LogStoreFailureCode::LimitExceeded);
    assert_eq!(block_bound.to_string(), "log store failure: LimitExceeded");
    Ok(())
}
