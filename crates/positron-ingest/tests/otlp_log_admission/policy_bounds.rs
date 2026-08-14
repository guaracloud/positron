use std::error::Error;

use positron_domain::routing::SignalKind;
use positron_domain::value::AttributeNamespace;
use positron_ingest::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyCompileFailure, PolicyPredicate,
    PolicyRule, PolicyTarget,
};

#[test]
fn compiler_rejects_identity_rule_predicate_path_and_byte_bound_violations()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        IngestPolicy::compile(0, Vec::new()).expect_err("zero generation"),
        PolicyCompileFailure::InvalidIdentity
    );

    let accept = PolicyRule::new("accept", Vec::new(), PolicyAction::Accept)?;
    assert_eq!(
        IngestPolicy::compile(1, vec![accept.clone(); 65]).expect_err("65 rules"),
        PolicyCompileFailure::RuleBoundExceeded
    );
    assert_eq!(
        PolicyRule::new(
            "too-many-predicates",
            vec![PolicyPredicate::signal_store(SignalKind::Logs); 17],
            PolicyAction::Accept,
        )
        .expect_err("17 predicates"),
        PolicyCompileFailure::PredicateBoundExceeded
    );
    assert_eq!(
        PolicyRule::new("", Vec::new(), PolicyAction::Accept).expect_err("empty rule ID"),
        PolicyCompileFailure::InvalidRuleId
    );
    assert_eq!(
        IngestPolicy::compile(1, vec![accept.clone(), accept]).expect_err("duplicate rule ID"),
        PolicyCompileFailure::InvalidRuleId
    );

    assert_eq!(
        PolicyAttributePath::new(AttributeNamespace::Record, "").expect_err("empty path"),
        PolicyCompileFailure::InvalidPath
    );
    let mut deep = PolicyAttributePath::new(AttributeNamespace::Record, "payload")?;
    for index in 0..16 {
        deep = deep.array_index(index)?;
    }
    assert_eq!(
        deep.array_index(16).expect_err("path depth 17"),
        PolicyCompileFailure::InvalidPath
    );

    let body = "x".repeat(262_144);
    let mut byte_heavy = Vec::new();
    for index in 0..5 {
        byte_heavy.push(PolicyRule::new(
            format!("body-{index}"),
            vec![PolicyPredicate::body_exact_text(body.clone())?],
            PolicyAction::Remove(PolicyTarget::body()),
        )?);
    }
    assert_eq!(
        IngestPolicy::compile(1, byte_heavy).expect_err("policy byte budget"),
        PolicyCompileFailure::PolicyBytesExceeded
    );
    let service = PolicyAttributePath::new(AttributeNamespace::Resource, "service.name")?;
    let protected = PolicyRule::new(
        "cannot-redact-service-identity",
        Vec::new(),
        PolicyAction::Redact(PolicyTarget::attribute(service)),
    )?;
    assert_eq!(
        IngestPolicy::compile(1, vec![protected]).expect_err("service identity is intrinsic"),
        PolicyCompileFailure::ProtectedTarget
    );
    Ok(())
}
