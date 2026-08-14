use positron_domain::identity::TenantId;
use positron_domain::value::AttributeNamespace;
use positron_policy::{
    IngestPolicy, MAX_ACTIVATED_POLICY_OBJECT_BYTES, PolicyAction, PolicyAttributePath,
    PolicyCompileFailure, PolicyPredicate, PolicyRule,
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
fn compiler_ceiling_is_the_exact_persisted_activation_object_size() {
    let tenant = TenantId::from_bytes([9; 16]).expect("tenant");
    let make_policy = |body: String| {
        IngestPolicy::compile(
            1,
            vec![
                PolicyRule::new(
                    "exact",
                    vec![PolicyPredicate::body_exact_text(body).expect("predicate")],
                    PolicyAction::Accept,
                )
                .expect("rule"),
            ],
        )
    };
    let empty_bytes = make_policy(String::new())
        .expect("empty body policy")
        .activated_object(tenant)
        .expect("activation")
        .into_bytes()
        .len();
    let exact_body_bytes = MAX_ACTIVATED_POLICY_OBJECT_BYTES - empty_bytes;
    let exact = make_policy("a".repeat(exact_body_bytes)).expect("exact maximum");
    assert_eq!(
        exact
            .activated_object(tenant)
            .expect("activation")
            .into_bytes()
            .len(),
        MAX_ACTIVATED_POLICY_OBJECT_BYTES,
    );
    assert_eq!(
        make_policy("a".repeat(exact_body_bytes + 1)).expect_err("one byte over"),
        PolicyCompileFailure::PolicyBytesExceeded,
    );
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
