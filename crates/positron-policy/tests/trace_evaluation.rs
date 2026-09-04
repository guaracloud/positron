use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
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
