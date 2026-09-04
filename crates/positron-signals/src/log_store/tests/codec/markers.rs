use super::*;

use positron_domain::value::{AttributeValueKind, MarkerAction};
use positron_policy::{
    IngestPolicy, NativeLogAttribute, NativeLogCandidate, PolicyAction, PolicyAttributePath,
    PolicyEvaluation, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};

#[test]
fn public_log_store_round_trip_preserves_policy_markers_without_source_payload()
-> Result<(), Box<dyn Error>> {
    let profile = value_profile()?;
    let secret_path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let payload_path = PolicyAttributePath::new(AttributeNamespace::Record, "payload")?;
    let nested_secret_path = payload_path.clone().key("nested")?;
    let removed_path = PolicyAttributePath::new(AttributeNamespace::Record, "removed")?;
    let policy = IngestPolicy::compile(
        11,
        vec![
            PolicyRule::new(
                "redact-secret",
                vec![PolicyPredicate::attribute_exists(secret_path.clone())],
                PolicyAction::Redact(PolicyTarget::attribute(secret_path)),
            )?,
            PolicyRule::new(
                "redact-nested-secret",
                vec![PolicyPredicate::attribute_exists(
                    nested_secret_path.clone(),
                )],
                PolicyAction::Redact(PolicyTarget::attribute(nested_secret_path)),
            )?,
            PolicyRule::new(
                "truncate-payload",
                vec![PolicyPredicate::attribute_exists(payload_path.clone())],
                PolicyAction::TruncateElements(PolicyTarget::attribute(payload_path), 1),
            )?,
            PolicyRule::new(
                "remove-attribute",
                vec![PolicyPredicate::attribute_exists(removed_path.clone())],
                PolicyAction::Remove(PolicyTarget::attribute(removed_path)),
            )?,
        ],
    )?;
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        vec![
            NativeLogAttribute::new(
                AttributeNamespace::Record,
                "secret".to_owned(),
                vec![CandidateAttributeValue::string("source-secret".to_owned())],
            ),
            NativeLogAttribute::new(
                AttributeNamespace::Record,
                "payload".to_owned(),
                vec![CandidateAttributeValue::key_value_list(vec![
                    CandidateKeyValue::new(
                        "nested".to_owned(),
                        CandidateAttributeValue::string("nested-source".to_owned()),
                    ),
                    CandidateKeyValue::new(
                        "visible".to_owned(),
                        CandidateAttributeValue::string("visible".to_owned()),
                    ),
                ])],
            ),
            NativeLogAttribute::new(
                AttributeNamespace::Record,
                "removed".to_owned(),
                vec![CandidateAttributeValue::string("removed-source".to_owned())],
            ),
        ],
        positron_policy::LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("policy unexpectedly rejected candidate".into());
    };
    let record = LogRecord::checked_evaluated(profile, *evaluated)?;
    let marker = record
        .attributes()
        .first()
        .ok_or("missing redacted attribute")?
        .occurrences()
        .occurrence(0)
        .ok_or("missing redacted occurrence")?;
    assert_eq!(marker.marker_action(), Some(MarkerAction::Redacted));
    assert_eq!(
        marker.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    let nested = record
        .attributes()
        .get(1)
        .ok_or("missing truncated payload")?
        .occurrences()
        .occurrence(0)
        .ok_or("missing truncated payload occurrence")?;
    assert_eq!(
        nested.truncation_action(),
        Some(MarkerAction::TruncatedElements)
    );
    assert_eq!(
        nested
            .key_value_entry(0)
            .and_then(|entry| entry.value().marker_action()),
        Some(MarkerAction::Redacted)
    );
    let removed = record
        .attributes()
        .get(2)
        .ok_or("missing removed attribute")?
        .occurrences()
        .occurrence(0)
        .ok_or("missing removed occurrence")?;
    assert_eq!(removed.marker_action(), Some(MarkerAction::Removed));
    assert_eq!(
        removed.marker_original_kind(),
        Some(AttributeValueKind::String)
    );

    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(71)?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x17; 16])?,
        CatalogSecret::from_owned(Box::new([0x27; 32]), Box::new([0x37; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )?;
    let store = LogStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &clock(1_000),
                tenant,
                shard,
                StoreBlockIdentity::new([0x67; 16])?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let payload = snapshot
        .blocks()
        .first()
        .ok_or("missing committed log block")?
        .payload();
    assert_eq!(u16::from_be_bytes([payload[8], payload[9]]), 3);
    assert!(
        !payload
            .windows("source-secret".len())
            .any(|window| window == b"source-secret")
    );
    assert!(
        !payload
            .windows("removed-source".len())
            .any(|window| window == b"removed-source")
    );
    let result = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(
        result
            .records()
            .first()
            .ok_or("missing scanned log")?
            .record(),
        &record
    );
    let scanned_payload = result.records()[0].record().attributes()[1]
        .occurrences()
        .occurrence(0)
        .ok_or("missing scanned payload")?;
    assert_eq!(
        scanned_payload
            .key_value_entry(0)
            .and_then(|entry| entry.value().marker_action()),
        Some(MarkerAction::Redacted)
    );
    assert_eq!(
        result.records()[0].record().attributes()[2]
            .occurrences()
            .occurrence(0)
            .and_then(|value| value.marker_action()),
        Some(MarkerAction::Removed)
    );
    Ok(())
}

fn literal_log_v2_block(tenant: TenantId, marker: bool) -> Vec<u8> {
    let mut bytes = b"PLOGBL01".to_vec();
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&5_i32.to_be_bytes());
    bytes.extend_from_slice(&4_u32.to_be_bytes());
    bytes.extend_from_slice(b"info");
    bytes.extend_from_slice(&5_u32.to_be_bytes());
    bytes.extend_from_slice(b"event");
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(b"res");
    bytes.extend_from_slice(&5_u32.to_be_bytes());
    bytes.extend_from_slice(b"scope");
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(b"1.0");
    bytes.extend_from_slice(&4_u32.to_be_bytes());
    bytes.extend_from_slice(&6_u32.to_be_bytes());
    bytes.extend_from_slice(b"scoped");
    bytes.extend_from_slice(&100_i64.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(1);
    bytes.push(3);
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(b"key");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    if marker {
        bytes.extend_from_slice(&[8, 1, 4]);
    } else {
        bytes.extend_from_slice(&[1, 1]);
    }
    bytes.extend_from_slice(&9_u64.to_be_bytes());
    bytes.extend_from_slice(&[0x13; 32]);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes
}

fn literal_log_v1_marker_block(tenant: TenantId) -> Vec<u8> {
    let mut bytes = b"PLOGBL01".to_vec();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(2);
    bytes.push(0);
    bytes.extend_from_slice(&100_i64.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(1);
    bytes.push(3);
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(b"key");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[8, 1, 4]);
    bytes.extend_from_slice(&9_u64.to_be_bytes());
    bytes.extend_from_slice(&[0x13; 32]);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes
}

#[test]
fn public_log_store_reads_literal_v1_v2_and_rejects_marker_tags_in_both()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1c; 16])?,
        CatalogSecret::from_owned(Box::new([0x2c; 32]), Box::new([0x3c; 32])),
    )?;
    for (index, (version, fixture)) in [
        (1_u16, encoded_log_fixture(tenant)),
        (2_u16, literal_log_v2_block(tenant, false)),
    ]
    .into_iter()
    .enumerate()
    {
        let shard = VirtualShardId::new(u32::try_from(73 + index)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0x61 + index)?; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(0x71 + index)?; 16])?,
            fixture,
        )?)?;
        let result = LogStore::new().scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            LogScan::all(ScanLimit::new(1)?),
        )?;
        let record = result
            .records()
            .first()
            .ok_or("missing literal legacy log")?
            .record();
        if version == 1 {
            assert_eq!(record.metadata(), &LogMetadata::empty());
            assert_eq!(record.attributes().len(), 1);
            assert_eq!(record.attributes()[0].occurrences().key(), "k");
            assert!(
                record.attributes()[0]
                    .occurrences()
                    .occurrence(0)
                    .is_some_and(positron_domain::value::ValidatedAttributeValue::is_null)
            );
        } else {
            assert_eq!(record.metadata().severity_number(), 5);
            assert_eq!(record.metadata().event_name(), "event");
            assert_eq!(
                record.attributes()[0]
                    .occurrences()
                    .occurrence(0)
                    .and_then(|value| value.as_boolean()),
                Some(true)
            );
        }
    }

    for (index, fixture) in [
        literal_log_v1_marker_block(tenant),
        literal_log_v2_block(tenant, true),
    ]
    .into_iter()
    .enumerate()
    {
        let shard = VirtualShardId::new(u32::try_from(75 + index)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0x65 + index)?; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(0x75 + index)?; 16])?,
            fixture,
        )?)?;
        let failure = LogStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                LogScan::all(ScanLimit::new(1)?),
            )
            .expect_err("legacy marker tag must be rejected");
        assert_eq!(failure.code(), LogStoreFailureCode::MalformedBlock);
    }
    Ok(())
}

#[test]
fn public_log_store_rejects_malformed_v3_marker_frames() -> Result<(), Box<dyn Error>> {
    let profile = value_profile()?;
    let body = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("sanitized".to_owned()),
        MarkerAction::TruncatedBytes,
    )
    .validate_log_body(profile)?;
    let attributes = vec![StoredLogAttribute::generic(occurrences(
        profile,
        AttributeNamespace::Record,
        "secret",
        vec![CandidateAttributeValue::redaction_marker(
            AttributeValueKind::String,
            MarkerAction::Removed,
        )],
    )?)];
    let record = LogRecord::checked_native(
        profile,
        EventTime::missing(),
        None,
        Some(body),
        attributes,
        LogMetadata::empty(),
        PolicyProvenance::new(13, [0x7a; 32], Vec::new())?,
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1d; 16])?,
        CatalogSecret::from_owned(Box::new([0x2d; 32]), Box::new([0x3d; 32])),
    )?;
    let store = LogStore::new();
    let source_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(101)?);
    let source_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        source_scope,
        SegmentProtectionKey::from_owned(Box::new([0x6d; 32])),
    )?;
    source_ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &clock(1_100),
                tenant,
                VirtualShardId::new(101)?,
                StoreBlockIdentity::new([0x7d; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    let valid = source_ledger
        .snapshot()?
        .blocks()
        .first()
        .ok_or("missing source log block")?
        .payload()
        .to_vec();
    let marker_offset = valid
        .windows(3)
        .position(|bytes| bytes == [8, 2, 4])
        .ok_or("missing v3 truncation marker")?;
    let mut unknown_action = valid.clone();
    unknown_action[marker_offset + 1] = 9;
    let mut unknown_kind = valid.clone();
    unknown_kind[marker_offset + 2] = 9;
    let mut mismatched_kind = valid.clone();
    mismatched_kind[marker_offset + 2] = 6;
    let mut nested_wrapper = valid.clone();
    nested_wrapper[marker_offset + 3] = 8;
    let mut trailing = valid.clone();
    trailing.push(0);
    let truncated = valid[..valid.len().saturating_sub(1)].to_vec();
    let mut legacy_tag = valid.clone();
    legacy_tag[8..10].copy_from_slice(&2_u16.to_be_bytes());

    for (index, bytes) in [
        unknown_action,
        unknown_kind,
        mismatched_kind,
        nested_wrapper,
        trailing,
        truncated,
        legacy_tag,
    ]
    .into_iter()
    .enumerate()
    {
        let shard = VirtualShardId::new(u32::try_from(102 + index)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0x70 + index)?; 32])),
        )?;
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(0x80 + index)?; 16])?,
            bytes,
        )?)?;
        let failure = store
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                LogScan::all(ScanLimit::new(1)?),
            )
            .expect_err("malformed v3 marker frame must fail closed");
        assert_eq!(failure.code(), LogStoreFailureCode::MalformedBlock);
    }
    Ok(())
}
