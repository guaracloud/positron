use positron_domain::routing::SignalKind;
use positron_domain::value::{
    AttributeNamespace, CandidateAttributeValue, CandidateKeyValue, MarkerAction,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyAction,
    PolicyAttributePath, PolicyEvaluation, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget,
};

fn attribute(key: &str, value: CandidateAttributeValue) -> NativeLogAttribute {
    NativeLogAttribute::new(AttributeNamespace::Record, key.into(), vec![value])
}

fn path(key: &str) -> PolicyAttributePath {
    PolicyAttributePath::new(AttributeNamespace::Record, key).expect("bounded path")
}

fn rule(id: &str, predicate: PolicyPredicate, action: PolicyAction) -> PolicyRule {
    PolicyRule::new(id, vec![predicate], action).expect("bounded rule")
}

#[test]
fn policy_predicates_fail_closed_for_missing_and_mismatched_paths() {
    let nested = path("nested");
    let array = nested.clone().key("array").expect("array path");
    let out_of_range = array.clone().array_index(1).expect("index path");
    let missing_key = nested.clone().key("missing").expect("missing path");
    let wrong_root = path("plain").key("child").expect("wrong root path");
    let wrong_kind = path("plain");

    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::bytes(vec![1, 2, 3])),
        vec![
            attribute(
                "nested",
                CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                    "array".into(),
                    CandidateAttributeValue::array(vec![CandidateAttributeValue::string(
                        "retained".into(),
                    )]),
                )]),
            ),
            attribute("plain", CandidateAttributeValue::string("text".into())),
        ],
        LogMetadata::empty(),
    );
    let rules = vec![
        rule(
            "body-text-mismatch",
            PolicyPredicate::body_exact_text("text").expect("body predicate"),
            PolicyAction::Reject,
        ),
        rule(
            "missing-attribute",
            PolicyPredicate::attribute_exists(path("missing")),
            PolicyAction::Reject,
        ),
        rule(
            "missing-key",
            PolicyPredicate::attribute_exists(missing_key),
            PolicyAction::Reject,
        ),
        rule(
            "wrong-root-container",
            PolicyPredicate::attribute_exists(wrong_root),
            PolicyAction::Reject,
        ),
        rule(
            "array-out-of-range",
            PolicyPredicate::attribute_exists(out_of_range.clone()),
            PolicyAction::Reject,
        ),
        rule(
            "array-type-out-of-range",
            PolicyPredicate::attribute_type(
                out_of_range,
                positron_domain::value::AttributeValueKind::String,
            ),
            PolicyAction::Reject,
        ),
        rule(
            "wrong-root-array-index",
            PolicyPredicate::attribute_exists(path("plain").array_index(0).expect("index")),
            PolicyAction::Reject,
        ),
        rule(
            "wrong-native-kind",
            PolicyPredicate::attribute_type(
                wrong_kind,
                positron_domain::value::AttributeValueKind::Bytes,
            ),
            PolicyAction::Reject,
        ),
        rule(
            "receiver-mismatch",
            PolicyPredicate::receiver(PolicyReceiver::OtlpHttpJson),
            PolicyAction::Reject,
        ),
        rule(
            "service-mismatch",
            PolicyPredicate::service_identity("missing").expect("service predicate"),
            PolicyAction::Reject,
        ),
        rule(
            "severity-mismatch",
            PolicyPredicate::log_severity(99),
            PolicyAction::Reject,
        ),
        rule(
            "accept-logs",
            PolicyPredicate::signal_store(SignalKind::Logs),
            PolicyAction::Accept,
        ),
    ];
    let policy = IngestPolicy::compile(12, rules).expect("policy");

    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("a nonmatching boundary predicate rejected the record");
    };
    let (_, _, body, attributes, _, provenance) = record.into_parts();
    assert_eq!(body, Some(CandidateAttributeValue::bytes(vec![1, 2, 3])));
    assert_eq!(attributes[1].occurrences()[0].as_str(), Some("text"));
    assert_eq!(provenance.applied_rules(), &["accept-logs"]);
}

#[test]
fn policy_transformations_leave_absent_or_incompatible_targets_unchanged() {
    let plain = path("plain");
    let array = path("array");
    let missing_child = array.clone().key("missing").expect("missing child");
    let missing_index = array.clone().array_index(3).expect("missing index");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        vec![
            attribute("plain", CandidateAttributeValue::boolean(true)),
            attribute(
                "array",
                CandidateAttributeValue::array(vec![CandidateAttributeValue::string(
                    "kept".into(),
                )]),
            ),
        ],
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        13,
        vec![
            rule(
                "remove-missing-body",
                PolicyPredicate::receiver(PolicyReceiver::OtlpGrpc),
                PolicyAction::Remove(PolicyTarget::body()),
            ),
            rule(
                "truncate-scalar-elements",
                PolicyPredicate::attribute_exists(plain.clone()),
                PolicyAction::TruncateElements(PolicyTarget::attribute(plain.clone()), 1),
            ),
            rule(
                "truncate-scalar-bytes",
                PolicyPredicate::attribute_exists(plain.clone()),
                PolicyAction::TruncateBytes(PolicyTarget::attribute(plain.clone()), 1),
            ),
            rule(
                "redact-plain",
                PolicyPredicate::attribute_exists(plain.clone()),
                PolicyAction::Redact(PolicyTarget::attribute(plain.clone())),
            ),
            rule(
                "redact-marker-noop",
                PolicyPredicate::attribute_exists(plain.clone()),
                PolicyAction::Redact(PolicyTarget::attribute(plain.clone())),
            ),
            rule(
                "redact-wrong-child",
                PolicyPredicate::attribute_exists(array.clone()),
                PolicyAction::Redact(PolicyTarget::attribute(missing_child)),
            ),
            rule(
                "redact-missing-index",
                PolicyPredicate::attribute_exists(array.clone()),
                PolicyAction::Redact(PolicyTarget::attribute(missing_index)),
            ),
            rule(
                "truncate-scalar-elements-again",
                PolicyPredicate::attribute_exists(plain.clone()),
                PolicyAction::TruncateElements(PolicyTarget::attribute(plain), 1),
            ),
            rule(
                "accept-logs",
                PolicyPredicate::signal_store(SignalKind::Logs),
                PolicyAction::Accept,
            ),
        ],
    )
    .expect("policy");

    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("record rejected");
    };
    let (_, _, body, attributes, _, provenance) = record.into_parts();
    assert!(body.is_none());
    assert!(matches!(
        attributes[0].occurrences(),
        [CandidateAttributeValue::Marker(marker)]
            if marker.action() == MarkerAction::Redacted
    ));
    assert!(matches!(
        attributes[1].occurrences(),
        [CandidateAttributeValue::Array(values)]
            if values[0].as_str() == Some("kept")
    ));
    assert_eq!(provenance.applied_rules(), &["redact-plain", "accept-logs"]);
}

#[test]
fn log_policy_reject_action_has_a_terminal_public_outcome() {
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("blocked".into())),
        Vec::new(),
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        14,
        vec![rule(
            "reject-blocked",
            PolicyPredicate::body_exact_text("blocked").expect("body predicate"),
            PolicyAction::Reject,
        )],
    )
    .expect("policy");

    assert_eq!(
        policy
            .evaluate(candidate, PolicyReceiver::OtlpHttpJson)
            .expect("evaluation"),
        PolicyEvaluation::Rejected
    );
}
