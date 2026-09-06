use positron_domain::value::{AttributeNamespace, AttributeValueKind, CandidateAttributeValue};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyAction,
    PolicyAttributePath, PolicyEvaluation, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget,
};

#[test]
fn truncation_then_native_type_accept_preserves_ordered_sanitized_provenance() {
    let text = PolicyAttributePath::new(AttributeNamespace::Record, "text").expect("path");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "text".to_owned(),
            vec![CandidateAttributeValue::string("source-text".to_owned())],
        )],
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        14,
        vec![
            PolicyRule::new(
                "truncate-text",
                vec![PolicyPredicate::attribute_exists(text.clone())],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(text.clone()), 6),
            )
            .expect("truncation rule"),
            PolicyRule::new(
                "accept-truncated-text",
                vec![PolicyPredicate::attribute_type(
                    text,
                    AttributeValueKind::String,
                )],
                PolicyAction::Accept,
            )
            .expect("typed acceptance rule"),
        ],
    )
    .expect("policy compiles");

    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("policy evaluation succeeds")
    else {
        panic!("truncated string should satisfy the native String predicate");
    };
    let (_, _, _, attributes, _, provenance) = record.into_parts();
    assert_eq!(
        attributes[0].occurrences()[0],
        CandidateAttributeValue::truncated(
            CandidateAttributeValue::string("source".to_owned()),
            positron_domain::value::MarkerAction::TruncatedBytes,
        )
    );
    assert_eq!(
        provenance.applied_rules(),
        &["truncate-text", "accept-truncated-text"]
    );
}
