use super::*;

use crate::{
    EvaluatedSpanObservationInput, SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails,
    SpanObservationDetailsInput, SpanResourceMetadata, SpanScopeMetadata, SpanStatus,
    SpanStatusCode, TraceQuietPeriod, TraceSummaryMaintainer,
};
use positron_domain::value::{AttributeValueKind, MarkerAction};
use positron_policy::{
    IngestPolicy, NativePolicyAttribute, NativeTraceCandidate, PolicyAction, PolicyAttributePath,
    PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget, TracePolicyEvaluation,
};

#[test]
fn public_trace_store_round_trip_preserves_markers_in_span_event_and_link_details()
-> Result<(), Box<dyn Error>> {
    let profile = TraceStore::value_limit_profile();
    let secret_path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let policy = IngestPolicy::compile(
        12,
        vec![PolicyRule::new(
            "redact-secret",
            vec![PolicyPredicate::attribute_exists(secret_path.clone())],
            PolicyAction::Redact(PolicyTarget::attribute(secret_path)),
        )?],
    )?;
    let evaluated = match policy.evaluate_trace(
        NativeTraceCandidate::new(vec![NativePolicyAttribute::new(
            AttributeNamespace::Record,
            "secret".to_owned(),
            vec![CandidateAttributeValue::string("source-secret".to_owned())],
        )]),
        PolicyReceiver::OtlpGrpc,
    )? {
        TracePolicyEvaluation::Accepted(evaluated) => *evaluated,
        TracePolicyEvaluation::Rejected => {
            return Err("trace policy unexpectedly rejected candidate".into());
        },
    };
    let event_attribute = SpanAttributeSet::checked_with_profile(
        "event-secret".to_owned(),
        vec![CandidateAttributeValue::redaction_marker(
            AttributeValueKind::String,
            MarkerAction::Redacted,
        )],
        &profile,
    )?;
    let event_truncated_attribute = SpanAttributeSet::checked_with_profile(
        "event-values".to_owned(),
        vec![CandidateAttributeValue::truncated(
            CandidateAttributeValue::array(vec![
                CandidateAttributeValue::string("visible".to_owned()),
                CandidateAttributeValue::redaction_marker(
                    AttributeValueKind::String,
                    MarkerAction::Removed,
                ),
            ]),
            MarkerAction::TruncatedElements,
        )],
        &profile,
    )?;
    let event_truncated_text_attribute = SpanAttributeSet::checked_with_profile(
        "event-text".to_owned(),
        vec![CandidateAttributeValue::truncated(
            CandidateAttributeValue::string("sanitized-event".to_owned()),
            MarkerAction::TruncatedBytes,
        )],
        &profile,
    )?;
    let link_attribute = SpanAttributeSet::checked_with_profile(
        "link-secret".to_owned(),
        vec![CandidateAttributeValue::redaction_marker(
            AttributeValueKind::Bytes,
            MarkerAction::Removed,
        )],
        &profile,
    )?;
    let link_truncated_attribute = SpanAttributeSet::checked_with_profile(
        "link-values".to_owned(),
        vec![CandidateAttributeValue::truncated(
            CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "nested".to_owned(),
                CandidateAttributeValue::redaction_marker(
                    AttributeValueKind::Bytes,
                    MarkerAction::Redacted,
                ),
            )]),
            MarkerAction::TruncatedElements,
        )],
        &profile,
    )?;
    let event = SpanEvent::checked_with_profile(
        EventTime::missing(),
        "event".to_owned(),
        vec![
            event_attribute,
            event_truncated_attribute,
            event_truncated_text_attribute,
        ],
        0,
        &profile,
    )?;
    let link = SpanLink::checked_with_profile(
        [0x72; 16],
        [0x73; 8],
        String::new(),
        0,
        vec![link_attribute, link_truncated_attribute],
        0,
        &profile,
    )?;
    let details = SpanObservationDetails::checked_with_profile(
        SpanObservationDetailsInput {
            trace_state: String::new(),
            flags: 0,
            status: SpanStatus::checked(SpanStatusCode::Unset, String::new())?,
            events: vec![event],
            links: vec![link],
            dropped_attributes_count: 0,
            dropped_events_count: 0,
            dropped_links_count: 0,
            resource: SpanResourceMetadata::checked(0, String::new())?,
            scope: SpanScopeMetadata::checked(String::new(), String::new(), 0, String::new())?,
        },
        &profile,
    )?;
    let observation = SpanObservation::checked_evaluated(
        profile,
        EvaluatedSpanObservationInput {
            trace_id: [0x61; 16],
            span_id: [0x62; 8],
            parent_span_id: None,
            name: "marker-span".to_owned(),
            start_time: EventTime::missing(),
            end_time: EventTime::missing(),
            kind: SpanKind::Internal,
            sampling: SamplingDecision::Unknown,
            evaluated,
            details,
        },
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(72)?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x69; 16])?,
                vec![observation.clone()],
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let payload = snapshot
        .blocks()
        .first()
        .ok_or("missing committed trace block")?
        .payload();
    assert_eq!(u16::from_be_bytes([payload[8], payload[9]]), 3);
    assert!(
        !payload
            .windows("source-secret".len())
            .any(|window| window == b"source-secret")
    );
    let result = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let actual = result
        .spans()
        .first()
        .and_then(|span| span.structural_representative())
        .ok_or("missing scanned logical trace")?
        .observation();
    assert_eq!(actual, &observation);
    assert_eq!(
        actual.attributes()[0]
            .occurrence(0)
            .and_then(|value| value.marker_action()),
        Some(MarkerAction::Redacted)
    );
    assert_eq!(
        actual.details().events()[0].attributes()[0]
            .occurrence(0)
            .and_then(|value| value.marker_action()),
        Some(MarkerAction::Redacted)
    );
    let event_values = actual.details().events()[0].attributes()[1]
        .occurrence(0)
        .ok_or("missing truncated event value")?;
    assert_eq!(
        event_values.truncation_action(),
        Some(MarkerAction::TruncatedElements)
    );
    assert!(
        event_values
            .array_entry(1)
            .is_some_and(|value| value.marker_action() == Some(MarkerAction::Removed))
    );
    let event_text = actual.details().events()[0].attributes()[2]
        .occurrence(0)
        .ok_or("missing truncated event text")?;
    assert_eq!(
        event_text.truncation_action(),
        Some(MarkerAction::TruncatedBytes)
    );
    assert_eq!(event_text.as_str(), Some("sanitized-event"));
    assert_eq!(
        actual.details().links()[0].attributes()[0]
            .occurrence(0)
            .and_then(|value| value.marker_action()),
        Some(MarkerAction::Removed)
    );
    let link_values = actual.details().links()[0].attributes()[1]
        .occurrence(0)
        .ok_or("missing truncated link value")?;
    assert_eq!(
        link_values.truncation_action(),
        Some(MarkerAction::TruncatedElements)
    );
    assert_eq!(
        link_values
            .key_value_entry(0)
            .and_then(|entry| entry.value().marker_action()),
        Some(MarkerAction::Redacted)
    );
    drop(result);
    let mut maintainer = TraceSummaryMaintainer::new(
        authority.governor(),
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        TraceQuietPeriod::new(5)?,
        ScanLimit::new(1)?,
    )?;
    let maintenance = maintainer.maintain(
        &store,
        &snapshot,
        &NeverCancelled,
        &NeverObserved,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
    )?;
    assert!(
        maintenance
            .summary([0x61; 16])
            .ok_or("missing marker-bearing summary")?
            .truncated(),
        "a retained truncation marker must propagate to its trace summary"
    );
    Ok(())
}

#[test]
fn public_trace_store_reopen_preserves_scalar_marker_kinds_and_actions()
-> Result<(), Box<dyn Error>> {
    let profile = TraceStore::value_limit_profile();
    let scalar_markers = [
        ("null", AttributeValueKind::Null, MarkerAction::Redacted),
        (
            "boolean",
            AttributeValueKind::Boolean,
            MarkerAction::Removed,
        ),
        (
            "signed",
            AttributeValueKind::SignedInteger,
            MarkerAction::Redacted,
        ),
        (
            "floating",
            AttributeValueKind::FloatingPoint,
            MarkerAction::Removed,
        ),
    ];
    let attributes = scalar_markers
        .into_iter()
        .map(|(key, kind, action)| {
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Record,
                key.to_owned(),
                vec![CandidateAttributeValue::redaction_marker(kind, action)],
            )
            .validate(profile)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observation = SpanObservation::checked_native(
        [0x77; 16],
        [0x78; 8],
        None,
        "scalar-markers".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        attributes,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(15, [0x79; 32], Vec::new())?,
    )?;

    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(74)?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1a; 16])?,
        CatalogSecret::from_owned(Box::new([0x2a; 32]), Box::new([0x3a; 32])),
    )?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
    let key = SegmentProtectionKey::from_owned(Box::new([0x5a; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key.clone())?;
    ledger.append(
        TraceStore::new()
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                positron_kernel::StoreBlockIdentity::new([0x6a; 16])?,
                vec![observation.clone()],
            )?
            .into_store_block(),
    )?;
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key)?;
    let result = TraceStore::new().scan_physical(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let actual = result
        .observations()
        .first()
        .ok_or("missing scalar-marker observation")?
        .observation();
    assert_eq!(actual, &observation);
    for ((_, expected_kind, expected_action), attribute) in
        scalar_markers.into_iter().zip(actual.attributes())
    {
        let value = attribute
            .occurrence(0)
            .ok_or("missing scalar-marker occurrence")?;
        assert_eq!(value.kind(), AttributeValueKind::Marker);
        assert_eq!(value.marker_original_kind(), Some(expected_kind));
        assert_eq!(value.marker_action(), Some(expected_action));
        assert_eq!(value.decoded_size_bytes(), Ok(0));
        assert!(!value.is_null());
    }
    Ok(())
}

#[test]
fn public_trace_store_rejects_malformed_v3_marker_frames_and_legacy_marker_tags()
-> Result<(), Box<dyn Error>> {
    let profile = TraceStore::value_limit_profile();
    let sanitized = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("sanitized".to_owned()),
        MarkerAction::TruncatedBytes,
    );
    let attributes = vec![
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![sanitized],
        )
        .validate(profile)?,
    ];
    let observation = SpanObservation::checked_native(
        [0x74; 16],
        [0x75; 8],
        None,
        "marker-malformed".to_owned(),
        EventTime::missing(),
        EventTime::missing(),
        attributes,
        SpanKind::Internal,
        SamplingDecision::Unknown,
        positron_policy::PolicyProvenance::new(1, [0x76; 32], Vec::new())?,
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let stored = StoredSpanObservation::new(
        observation,
        LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)))
            .assign_ingest_time()?,
    );
    let valid = codec::encode_block(tenant, std::slice::from_ref(&stored))?;
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
    let malformed = [
        unknown_action,
        unknown_kind,
        mismatched_kind,
        nested_wrapper,
        trailing,
        truncated,
        legacy_tag,
    ];

    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1a; 16])?,
        CatalogSecret::from_owned(Box::new([0x2a; 32]), Box::new([0x3a; 32])),
    )?;
    for (index, bytes) in malformed.into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(80 + index)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0x70 + index)?; 32])),
        )?;
        ledger.append(positron_kernel::PreparedStoreBlock::new(
            scope,
            positron_kernel::StoreBlockIdentity::new([u8::try_from(0x80 + index)?; 16])?,
            bytes,
        )?)?;
        let failure = TraceStore::new()
            .scan(
                authority.governor(),
                tenant,
                &ledger.snapshot()?,
                TraceScan::all(ScanLimit::new(1)?),
            )
            .expect_err("malformed v3 marker frame must fail closed");
        assert_eq!(failure.code(), TraceStoreFailureCode::MalformedBlock);
    }
    Ok(())
}

fn literal_legacy_trace_block(tenant: TenantId, version: u16) -> Vec<u8> {
    let mut bytes = b"PTRCBL01".to_vec();
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&tenant.to_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.extend_from_slice(&[0x12; 8]);
    bytes.push(0);
    bytes.push(1);
    bytes.push(0);
    bytes.push(2);
    bytes.push(2);
    bytes.extend_from_slice(&6_u32.to_be_bytes());
    bytes.extend_from_slice(b"legacy");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(3);
    bytes.extend_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(b"key");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(1);
    bytes.push(1);
    if version == 2 {
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(b"ts");
        bytes.extend_from_slice(&7_u32.to_be_bytes());
        bytes.push(2);
        bytes.extend_from_slice(&5_u32.to_be_bytes());
        bytes.extend_from_slice(b"error");
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(&4_u32.to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(b"res");
        bytes.extend_from_slice(&5_u32.to_be_bytes());
        bytes.extend_from_slice(b"scope");
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(b"1.0");
        bytes.extend_from_slice(&5_u32.to_be_bytes());
        bytes.extend_from_slice(&6_u32.to_be_bytes());
        bytes.extend_from_slice(b"scoped");
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
    }
    bytes.extend_from_slice(&9_u64.to_be_bytes());
    bytes.extend_from_slice(&[0x13; 32]);
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&100_i64.to_be_bytes());
    bytes
}

#[test]
fn public_trace_store_reads_independent_literal_v1_and_v2_blocks() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1b; 16])?,
        CatalogSecret::from_owned(Box::new([0x2b; 32]), Box::new([0x3b; 32])),
    )?;
    for (index, version) in [1_u16, 2_u16].into_iter().enumerate() {
        let shard = VirtualShardId::new(u32::try_from(90 + index)?)?;
        let scope = SegmentScope::new(tenant, SignalKind::Traces, shard);
        let ledger = ActiveSegmentLedger::open(
            &authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([u8::try_from(0x60 + index)?; 32])),
        )?;
        let fixture = literal_legacy_trace_block(tenant, version);
        ledger.append(PreparedStoreBlock::new(
            scope,
            StoreBlockIdentity::new([u8::try_from(0x70 + index)?; 16])?,
            fixture,
        )?)?;
        let result = TraceStore::new().scan_physical(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )?;
        let observation = result
            .observations()
            .first()
            .ok_or("missing literal legacy trace")?
            .observation();
        assert_eq!(observation.name(), "legacy");
        assert_eq!(
            observation.attributes()[0]
                .occurrence(0)
                .and_then(|value| value.as_boolean()),
            Some(true)
        );
        if version == 1 {
            assert!(observation.details().events().is_empty());
            assert_eq!(observation.details().trace_state(), "");
        } else {
            assert_eq!(observation.details().trace_state(), "ts");
            assert_eq!(observation.details().flags(), 7);
            assert_eq!(observation.details().status().code(), SpanStatusCode::Error);
            assert_eq!(observation.details().status().message(), "error");
            assert_eq!(observation.details().scope().schema_url(), "scoped");
        }
    }
    Ok(())
}
