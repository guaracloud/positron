use positron_domain::identity::TenantId;
use positron_domain::value::AttributeNamespace;
use positron_policy::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyCompileFailure, PolicyPredicate,
    PolicyRule,
};

#[test]
fn activated_object_round_trips_exact_policy_and_is_tenant_scoped() {
    let tenant = TenantId::from_bytes([7; 16]).expect("tenant");
    let policy = IngestPolicy::compile(
        9,
        vec![PolicyRule::new("accept", Vec::new(), PolicyAction::Accept).expect("rule")],
    )
    .expect("policy");
    let bytes = policy
        .activated_object(tenant)
        .expect("activation")
        .into_bytes();
    let decoded = IngestPolicy::decode_activated_object(tenant, &bytes)
        .expect("decode")
        .expect("matching tenant");

    assert_eq!(decoded.generation(), policy.generation());
    assert_eq!(decoded.digest(), policy.digest());
    assert!(
        IngestPolicy::decode_activated_object(
            TenantId::from_bytes([8; 16]).expect("other tenant"),
            &bytes,
        )
        .expect("tenant mismatch is not corruption")
        .is_none()
    );
    let mut corrupt = bytes;
    corrupt.push(1);
    assert!(IngestPolicy::decode_activated_object(tenant, &corrupt).is_err());
}

#[test]
fn compiler_rejects_malicious_worst_case_steps_and_reports_full_memory() {
    let preserving = IngestPolicy::preserving(1).expect("policy");
    assert_eq!(preserving.budget().evaluation_steps(), 0);
    assert!(
        preserving
            .budget()
            .reserved_memory_bytes()
            .is_some_and(|bytes| bytes > 1_048_576)
    );

    let mut path =
        PolicyAttributePath::new(AttributeNamespace::Record, "payload").expect("root path");
    for index in 0..16 {
        path = path.array_index(index).expect("bounded path");
    }
    let predicates = vec![PolicyPredicate::attribute_exists(path); 6];
    let rule = PolicyRule::new("malicious", predicates, PolicyAction::Accept).expect("rule");
    assert_eq!(
        IngestPolicy::compile(1, vec![rule]).expect_err("step ceiling"),
        PolicyCompileFailure::EvaluationBudgetExceeded,
    );
}
