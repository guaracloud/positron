use super::super::*;
use crate::{TraceServiceIdentity, TraceStoreFailure};
use positron_domain::value::{AttributeOccurrenceSet, AttributeValueKind, MarkerAction};

fn resource_attribute(
    key: &str,
    values: Vec<CandidateAttributeValue>,
) -> Result<AttributeOccurrenceSet, TraceStoreFailure> {
    AttributeOccurrenceSetCandidate::new(AttributeNamespace::Resource, key.to_owned(), values)
        .validate(ValueLimitProfile::release_1_system_maximum())
        .map_err(TraceStoreFailure::domain)
}

#[test]
fn service_relationships_distinguish_untrusted_identity_states() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(91)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
    )?;
    let observation = |span_id, parent_span_id, attributes| {
        SpanObservation::checked_native(
            [0x95; 16],
            span_id,
            parent_span_id,
            "operation".to_owned(),
            EventTime::received(UnixNanoseconds::new(1), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            EventTime::received(UnixNanoseconds::new(2), SourceTimeQuality::Usable)
                .map_err(TraceStoreFailure::domain)?,
            attributes,
            SpanKind::Internal,
            SamplingDecision::Sampled,
            positron_policy::PolicyProvenance::new(1, [0x96; 32], Vec::new())?,
        )
    };
    let name = |value| resource_attribute("service.name", vec![value]);
    let namespace = |value| resource_attribute("service.namespace", vec![value]);
    let root_attributes = vec![
        name(CandidateAttributeValue::string("checkout".to_owned()))?,
        namespace(CandidateAttributeValue::string("storefront".to_owned()))?,
    ];
    let duplicate_name_attributes = vec![
        name(CandidateAttributeValue::string("inventory".to_owned()))?,
        name(CandidateAttributeValue::string("billing".to_owned()))?,
    ];
    let multi_value_name_attributes = vec![resource_attribute(
        "service.name",
        vec![
            CandidateAttributeValue::string("catalog".to_owned()),
            CandidateAttributeValue::string("shadow".to_owned()),
        ],
    )?];
    let non_string_name_attributes = vec![name(CandidateAttributeValue::boolean(true))?];
    let marker_name_attributes = vec![name(CandidateAttributeValue::redaction_marker(
        AttributeValueKind::String,
        MarkerAction::Redacted,
    ))?];
    let removed_name_attributes = vec![name(CandidateAttributeValue::redaction_marker(
        AttributeValueKind::String,
        MarkerAction::Removed,
    ))?];
    let truncated_name_attributes = vec![name(CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("sanitized".to_owned()),
        MarkerAction::TruncatedBytes,
    ))?];
    let absent_namespace_attributes = vec![name(CandidateAttributeValue::string(
        "absent-namespace".to_owned(),
    ))?];
    let invalid_namespace_attributes = vec![
        name(CandidateAttributeValue::string(
            "invalid-namespace".to_owned(),
        ))?,
        namespace(CandidateAttributeValue::boolean(true))?,
    ];
    let ambiguous_namespace_attributes = vec![
        name(CandidateAttributeValue::string(
            "ambiguous-namespace".to_owned(),
        ))?,
        namespace(CandidateAttributeValue::string("one".to_owned()))?,
        namespace(CandidateAttributeValue::string("two".to_owned()))?,
    ];
    let store = TraceStore::new();
    ledger.append(
        store
            .prepare_unretained_for_test(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x97; 16])?,
                vec![
                    observation([0x01; 8], None, root_attributes)?,
                    observation([0x02; 8], Some([0x01; 8]), duplicate_name_attributes)?,
                    observation([0x03; 8], Some([0x01; 8]), multi_value_name_attributes)?,
                    observation([0x04; 8], Some([0x01; 8]), non_string_name_attributes)?,
                    observation([0x05; 8], Some([0x01; 8]), marker_name_attributes)?,
                    observation([0x06; 8], Some([0x01; 8]), removed_name_attributes)?,
                    observation([0x07; 8], Some([0x01; 8]), truncated_name_attributes)?,
                    observation([0x08; 8], Some([0x01; 8]), absent_namespace_attributes)?,
                    observation([0x09; 8], Some([0x01; 8]), invalid_namespace_attributes)?,
                    observation([0x0a; 8], Some([0x01; 8]), ambiguous_namespace_attributes)?,
                ],
            )?
            .into_store_block(),
    )?;

    let mut trace = store.trace_by_id(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        [0x95; 16],
        TraceSearch::all(ScanLimit::new(10)?),
    )?;
    let structure = trace.analyze_structure(&NeverCancelled, &NeverObserved)?;
    assert!(structure.complete());
    let relationships = structure.service_relationships();
    assert!(!relationships.complete());
    assert_eq!(relationships.edges().len(), 9);

    let edge = |child_span_id| {
        relationships
            .edges()
            .iter()
            .find(|edge| edge.child_span_id() == child_span_id)
            .ok_or("missing service relationship")
    };
    for (child_span_id, identity) in [
        ([0x02; 8], TraceServiceIdentity::Ambiguous),
        ([0x03; 8], TraceServiceIdentity::Ambiguous),
        ([0x04; 8], TraceServiceIdentity::Invalid),
        ([0x05; 8], TraceServiceIdentity::Redacted),
        ([0x06; 8], TraceServiceIdentity::Removed),
        ([0x07; 8], TraceServiceIdentity::Truncated),
    ] {
        let relationship = edge(child_span_id)?;
        assert_eq!(relationship.parent_service(), Some("checkout"));
        assert_eq!(relationship.parent_service_namespace(), Some("storefront"));
        assert_eq!(relationship.child_service(), None);
        assert_eq!(relationship.child_identity(), identity);
    }

    let absent_namespace = edge([0x08; 8])?;
    assert_eq!(absent_namespace.child_service(), Some("absent-namespace"));
    assert_eq!(absent_namespace.child_service_namespace(), None);
    assert_eq!(
        absent_namespace.child_service_namespace_identity(),
        TraceServiceIdentity::Missing
    );
    let invalid_namespace = edge([0x09; 8])?;
    assert_eq!(invalid_namespace.child_service(), Some("invalid-namespace"));
    assert_eq!(invalid_namespace.child_service_namespace(), None);
    assert_eq!(
        invalid_namespace.child_service_namespace_identity(),
        TraceServiceIdentity::Invalid
    );
    let ambiguous_namespace = edge([0x0a; 8])?;
    assert_eq!(
        ambiguous_namespace.child_service(),
        Some("ambiguous-namespace")
    );
    assert_eq!(ambiguous_namespace.child_service_namespace(), None);
    assert_eq!(
        ambiguous_namespace.child_service_namespace_identity(),
        TraceServiceIdentity::Ambiguous
    );
    Ok(())
}
