use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_policy::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyRule, PolicyTarget,
};

#[test]
fn digest_is_generation_independent_and_changes_for_every_semantic_dimension() {
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")
        .expect("bounded path")
        .array_index(2)
        .expect("bounded segment");
    let first = PolicyRule::new(
        "first",
        vec![PolicyPredicate::attribute_type(
            path.clone(),
            AttributeValueKind::String,
        )],
        PolicyAction::TruncateBytes(PolicyTarget::attribute(path.clone()), 8),
    )
    .expect("bounded rule");
    let second = PolicyRule::new(
        "second",
        vec![PolicyPredicate::log_severity(13)],
        PolicyAction::Accept,
    )
    .expect("bounded rule");
    let baseline =
        IngestPolicy::compile(1, vec![first.clone(), second.clone()]).expect("canonical policy");
    let another_generation =
        IngestPolicy::compile(2, vec![first.clone(), second.clone()]).expect("same semantics");
    assert_eq!(baseline.digest(), another_generation.digest());

    let reordered = IngestPolicy::compile(1, vec![second, first.clone()]).expect("reordered");
    assert_ne!(baseline.digest(), reordered.digest());
    let changed_limit = IngestPolicy::compile(
        1,
        vec![
            PolicyRule::new(
                "first",
                vec![PolicyPredicate::attribute_type(
                    path.clone(),
                    AttributeValueKind::String,
                )],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(path.clone()), 7),
            )
            .expect("changed limit"),
        ],
    )
    .expect("changed policy");
    assert_ne!(baseline.digest(), changed_limit.digest());
    let changed_action = IngestPolicy::compile(
        1,
        vec![
            PolicyRule::new(
                "first",
                vec![PolicyPredicate::attribute_type(
                    path.clone(),
                    AttributeValueKind::String,
                )],
                PolicyAction::Redact(PolicyTarget::attribute(path)),
            )
            .expect("changed action"),
        ],
    )
    .expect("changed policy");
    assert_ne!(baseline.digest(), changed_action.digest());
}
