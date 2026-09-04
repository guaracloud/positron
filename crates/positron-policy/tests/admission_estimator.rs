use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_policy::{
    IngestPolicy, PolicyAction, PolicyAdmissionShape, PolicyAttributePath, PolicyPredicate,
    PolicyReceiver, PolicyRule, PolicyTarget,
};

fn path(key: &str) -> PolicyAttributePath {
    PolicyAttributePath::new(AttributeNamespace::Record, key).expect("bounded path")
}

#[test]
fn candidate_aware_work_is_small_for_tiny_shapes_and_additive_per_record() {
    let path = path("secret");
    let policy = IngestPolicy::compile(
        1,
        vec![
            PolicyRule::new(
                "redact-secret",
                Vec::new(),
                PolicyAction::Redact(PolicyTarget::attribute(path)),
            )
            .expect("bounded rule"),
        ],
    )
    .expect("bounded policy");
    let shape = PolicyAdmissionShape::from_bounded_decode(8, 128, 3, 1, 1);

    assert_eq!(policy.admission_cpu_work_units(&[shape]), Some(1));
    assert_eq!(policy.admission_cpu_work_units(&[shape, shape]), Some(2));
}

#[test]
fn candidate_aware_work_falls_back_on_checked_overflow_and_large_shapes_remain_costly() {
    let path = path("secret");
    let policy = IngestPolicy::compile(
        2,
        vec![
            PolicyRule::new(
                "redact-secret",
                vec![PolicyPredicate::attribute_exists(path.clone())],
                PolicyAction::Redact(PolicyTarget::attribute(path)),
            )
            .expect("bounded rule"),
        ],
    )
    .expect("bounded policy");
    let large = PolicyAdmissionShape::from_bounded_decode(1_048_576, 1_048_576, 4_096, 1_024, 16);
    assert!(
        policy
            .admission_cpu_work_units(&[large])
            .is_some_and(|units| units > 1)
    );

    let overflowing = PolicyAdmissionShape::from_bounded_decode(u64::MAX, 0, 0, 0, 0);
    assert_eq!(policy.admission_cpu_work_units(&[overflowing]), None);
}

#[test]
fn estimator_covers_every_compiled_predicate_and_action_variant() {
    let attribute = path("secret");
    let nested = path("nested").key("child").expect("bounded path");
    let rules = vec![
        PolicyRule::new(
            "exists",
            vec![PolicyPredicate::attribute_exists(attribute.clone())],
            PolicyAction::Accept,
        )
        .expect("rule"),
        PolicyRule::new(
            "type",
            vec![PolicyPredicate::attribute_type(
                attribute.clone(),
                AttributeValueKind::String,
            )],
            PolicyAction::Remove(PolicyTarget::attribute(attribute.clone())),
        )
        .expect("rule"),
        PolicyRule::new(
            "body",
            vec![PolicyPredicate::body_exact_text("body").expect("predicate")],
            PolicyAction::Redact(PolicyTarget::body()),
        )
        .expect("rule"),
        PolicyRule::new(
            "signal",
            vec![PolicyPredicate::signal_store(SignalKind::Logs)],
            PolicyAction::TruncateBytes(PolicyTarget::attribute(nested.clone()), 4),
        )
        .expect("rule"),
        PolicyRule::new(
            "receiver",
            vec![PolicyPredicate::receiver(PolicyReceiver::OtlpHttpProtobuf)],
            PolicyAction::TruncateElements(PolicyTarget::attribute(nested), 2),
        )
        .expect("rule"),
        PolicyRule::new(
            "service",
            vec![PolicyPredicate::service_identity("checkout").expect("predicate")],
            PolicyAction::Reject,
        )
        .expect("rule"),
        PolicyRule::new(
            "severity",
            vec![PolicyPredicate::log_severity(13)],
            PolicyAction::Accept,
        )
        .expect("rule"),
    ];
    let policy = IngestPolicy::compile(3, rules).expect("bounded policy");
    let shape = PolicyAdmissionShape::from_bounded_decode(128, 256, 8, 3, 2);
    assert!(
        policy
            .admission_cpu_work_units(&[shape])
            .is_some_and(|units| units >= 1)
    );
}
