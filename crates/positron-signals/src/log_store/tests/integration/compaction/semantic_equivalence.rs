use super::*;

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
