use super::*;

#[test]
fn committed_native_log_survives_reopen_and_bounded_scan() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x11; 16])?,
        CatalogSecret::from_owned(Box::new([0x21; 32]), Box::new([0x31; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x51; 32]));
    let store = LogStore::new();
    let record = LogRecord::checked_minimal(
        None,
        Some(String::new()),
        vec![
            ("resource", "service.name", "api"),
            ("scope", "version", ""),
            ("record", "attempt", "first"),
            ("record", "attempt", "second"),
        ],
        PolicyProvenance::new(7, [0x71; 32], vec!["redact-password".to_owned()])?,
    )?;
    let prepared = store.prepare(
        preparation_capacity(&authority, tenant)?,
        &clock(1_723_456_789_000_000_000),
        tenant,
        VirtualShardId::new(1)?,
        StoreBlockIdentity::new([0x61; 16])?,
        vec![record.clone()],
    )?;
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    ledger.append(prepared.into_store_block())?;
    drop(ledger);
    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records()[0].record(), &record);
    assert!(result.complete());
    Ok(())
}

#[test]
fn native_values_occurrences_namespaces_and_time_provenance_round_trip()
-> Result<(), Box<dyn Error>> {
    let profile = value_profile()?;
    let attributes = vec![
        StoredLogAttribute::generic(occurrences(
            profile,
            AttributeNamespace::Resource,
            "same-key",
            vec![CandidateAttributeValue::string("resource".to_owned())],
        )?),
        StoredLogAttribute::schema_overflow(occurrences(
            profile,
            AttributeNamespace::InstrumentationScope,
            "same-key",
            vec![CandidateAttributeValue::bytes(vec![])],
        )?),
        StoredLogAttribute::generic(occurrences(
            profile,
            AttributeNamespace::Record,
            "same-key",
            vec![
                CandidateAttributeValue::null(),
                CandidateAttributeValue::boolean(false),
                CandidateAttributeValue::signed_integer(-42),
                CandidateAttributeValue::floating_point_bits(f64::NAN.to_bits()),
                CandidateAttributeValue::string(String::new()),
                CandidateAttributeValue::bytes(vec![0, 255]),
                CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::signed_integer(7),
                    CandidateAttributeValue::string("seven".to_owned()),
                ]),
                CandidateAttributeValue::key_value_list(vec![
                    CandidateKeyValue::new(
                        "duplicate".to_owned(),
                        CandidateAttributeValue::boolean(true),
                    ),
                    CandidateKeyValue::new(
                        "duplicate".to_owned(),
                        CandidateAttributeValue::signed_integer(9),
                    ),
                ]),
            ],
        )?),
    ];
    let body = value(
        profile,
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "message".to_owned(),
            CandidateAttributeValue::string(String::new()),
        )]),
    )?;
    let record = LogRecord::checked_native(
        profile,
        EventTime::received(UnixNanoseconds::new(-55), SourceTimeQuality::Outlier)?,
        Some(ObservedTime::received(
            UnixNanoseconds::new(88),
            SourceTimeQuality::Usable,
        )?),
        Some(body),
        attributes,
        PolicyProvenance::new(9, [0x79; 32], vec![])?,
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let store = LogStore::new();
    let prepared = store.prepare(
        preparation_capacity(&authority, tenant)?,
        &clock(1_000),
        tenant,
        VirtualShardId::new(2)?,
        StoreBlockIdentity::new([0x62; 16])?,
        vec![record.clone()],
    )?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x12; 16])?,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x32; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?),
        SegmentProtectionKey::from_owned(Box::new([0x52; 32])),
    )?;
    ledger.append(prepared.into_store_block())?;
    let result = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records()[0].record(), &record);
    assert_eq!(
        result.records()[0].attributes()[1].representation(),
        AttributeRepresentation::SchemaOverflow
    );
    assert_eq!(
        StoredLogAttribute::generic(result.records()[0].attributes()[1].occurrences().clone()),
        result.records()[0].attributes()[1]
    );
    Ok(())
}
