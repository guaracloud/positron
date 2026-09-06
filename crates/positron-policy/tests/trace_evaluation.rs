use positron_domain::routing::SignalKind;
use positron_domain::value::{
    AttributeNamespace, AttributeValueKind, CandidateAttributeValue, MarkerAction,
};
use positron_policy::{
    IngestPolicy, NativeTraceCandidate, PolicyAction, PolicyAttributePath, PolicyEvaluation,
    PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget, TracePolicyEvaluation,
};

#[test]
fn trace_policy_transforms_generic_attributes_and_records_snapshot() {
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret").expect("path");
    let candidate = NativeTraceCandidate::new(vec![positron_policy::NativePolicyAttribute::new(
        AttributeNamespace::Record,
        "secret".into(),
        vec![CandidateAttributeValue::string("private".into())],
    )]);
    let policy = IngestPolicy::compile(
        7,
        vec![
            PolicyRule::new(
                "trace-redact",
                vec![
                    PolicyPredicate::signal_store(SignalKind::Traces),
                    PolicyPredicate::attribute_exists(path.clone()),
                ],
                PolicyAction::Redact(PolicyTarget::attribute(path)),
            )
            .expect("rule"),
        ],
    )
    .expect("policy");

    let TracePolicyEvaluation::Accepted(record) = policy
        .evaluate_trace(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("trace was unexpectedly rejected")
    };

    assert!(matches!(
        record.attributes()[0].occurrences(),
        [CandidateAttributeValue::Marker(marker)]
            if marker.action() == MarkerAction::Redacted
                && marker.original_kind() == AttributeValueKind::String
    ));
    assert!(!matches!(
        record.attributes()[0].occurrences(),
        [CandidateAttributeValue::Null]
    ));
    assert_eq!(record.policy_provenance().generation(), 7);
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &["trace-redact"]
    );
}

#[test]
fn trace_policy_rejects_only_the_candidate_when_trace_rule_matches() {
    let candidate = NativeTraceCandidate::new(vec![positron_policy::NativePolicyAttribute::new(
        AttributeNamespace::Resource,
        "service.name".into(),
        vec![CandidateAttributeValue::string("api".into())],
    )]);
    let policy = IngestPolicy::compile(
        8,
        vec![
            PolicyRule::new(
                "reject-traces",
                vec![PolicyPredicate::signal_store(SignalKind::Traces)],
                PolicyAction::Reject,
            )
            .expect("rule"),
        ],
    )
    .expect("policy");

    assert_eq!(
        policy
            .evaluate_trace(candidate, PolicyReceiver::OtlpHttpJson)
            .expect("evaluation"),
        TracePolicyEvaluation::Rejected
    );
}

#[test]
fn trace_policy_signal_predicate_does_not_change_log_evaluation() {
    let candidate = positron_policy::NativeLogCandidate::new(
        None,
        None,
        None,
        Vec::new(),
        positron_policy::LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        9,
        vec![
            PolicyRule::new(
                "trace-only",
                vec![PolicyPredicate::signal_store(SignalKind::Traces)],
                PolicyAction::Reject,
            )
            .expect("rule"),
        ],
    )
    .expect("policy");

    assert!(matches!(
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc),
        Ok(PolicyEvaluation::Accepted(_))
    ));
}

#[test]
fn trace_policy_preserves_typed_truncation_and_noop_target_boundaries() {
    let missing = PolicyAttributePath::new(AttributeNamespace::Record, "missing").expect("path");
    let text = PolicyAttributePath::new(AttributeNamespace::Record, "text").expect("path");
    let bytes = PolicyAttributePath::new(AttributeNamespace::Record, "bytes").expect("path");
    let array = PolicyAttributePath::new(AttributeNamespace::Record, "array").expect("path");
    let array_entry = array.clone().array_index(0).expect("array index");
    let candidate = NativeTraceCandidate::new(vec![
        positron_policy::NativePolicyAttribute::new(
            AttributeNamespace::Record,
            "text".into(),
            vec![CandidateAttributeValue::string("private".into())],
        ),
        positron_policy::NativePolicyAttribute::new(
            AttributeNamespace::Record,
            "bytes".into(),
            vec![CandidateAttributeValue::bytes(vec![1, 2, 3])],
        ),
        positron_policy::NativePolicyAttribute::new(
            AttributeNamespace::Record,
            "array".into(),
            vec![CandidateAttributeValue::array(vec![
                CandidateAttributeValue::string("first".into()),
                CandidateAttributeValue::string("second".into()),
            ])],
        ),
        positron_policy::NativePolicyAttribute::new(
            AttributeNamespace::Resource,
            "service.name".into(),
            vec![CandidateAttributeValue::string("api".into())],
        ),
    ]);
    let policy = IngestPolicy::compile(
        10,
        vec![
            PolicyRule::new(
                "trace-body-noop",
                vec![PolicyPredicate::receiver(PolicyReceiver::OtlpGrpc)],
                PolicyAction::Remove(PolicyTarget::body()),
            )
            .expect("body target rule"),
            PolicyRule::new(
                "trace-severity-noop",
                vec![PolicyPredicate::log_severity(1)],
                PolicyAction::Reject,
            )
            .expect("severity predicate rule"),
            PolicyRule::new(
                "trace-service-noop",
                vec![PolicyPredicate::service_identity("api").expect("service predicate")],
                PolicyAction::Remove(PolicyTarget::attribute(missing.clone())),
            )
            .expect("service rule"),
            PolicyRule::new(
                "trace-text-truncate",
                vec![PolicyPredicate::attribute_exists(text.clone())],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(text), 3),
            )
            .expect("text truncation rule"),
            PolicyRule::new(
                "trace-bytes-truncate",
                vec![PolicyPredicate::attribute_exists(bytes.clone())],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(bytes), 2),
            )
            .expect("bytes truncation rule"),
            PolicyRule::new(
                "trace-array-truncate",
                vec![PolicyPredicate::attribute_exists(array.clone())],
                PolicyAction::TruncateElements(PolicyTarget::attribute(array), 1),
            )
            .expect("array truncation rule"),
            PolicyRule::new(
                "trace-array-redact",
                vec![PolicyPredicate::attribute_exists(array_entry.clone())],
                PolicyAction::Redact(PolicyTarget::attribute(array_entry)),
            )
            .expect("nested redaction rule"),
            PolicyRule::new(
                "trace-missing-remove",
                vec![PolicyPredicate::attribute_exists(missing.clone())],
                PolicyAction::Remove(PolicyTarget::attribute(missing)),
            )
            .expect("missing target rule"),
            PolicyRule::new(
                "trace-accept",
                vec![PolicyPredicate::receiver(PolicyReceiver::OtlpGrpc)],
                PolicyAction::Accept,
            )
            .expect("accept rule"),
        ],
    )
    .expect("policy");

    let TracePolicyEvaluation::Accepted(record) = policy
        .evaluate_trace(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("trace was unexpectedly rejected")
    };
    let attributes = record.attributes();
    assert_eq!(attributes[0].occurrences()[0].as_str(), Some("pri"));
    assert_eq!(
        attributes[0].occurrences()[0].truncation_action(),
        Some(MarkerAction::TruncatedBytes)
    );
    assert_eq!(
        attributes[1].occurrences()[0],
        CandidateAttributeValue::Truncated {
            value: Box::new(CandidateAttributeValue::bytes(vec![1, 2])),
            action: MarkerAction::TruncatedBytes,
        }
    );
    assert!(matches!(
        &attributes[2].occurrences()[0],
        CandidateAttributeValue::Truncated { value, action }
            if *action == MarkerAction::TruncatedElements
                && matches!(value.as_ref(), CandidateAttributeValue::Array(values)
                    if matches!(values.as_slice(), [CandidateAttributeValue::Marker(marker)]
                        if marker.action() == MarkerAction::Redacted))
    ));
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &[
            "trace-text-truncate",
            "trace-bytes-truncate",
            "trace-array-truncate",
            "trace-array-redact",
            "trace-accept"
        ]
    );
}
