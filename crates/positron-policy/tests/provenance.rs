use positron_policy::PolicyProvenance;

#[test]
fn durable_provenance_reconstruction_enforces_policy_owned_bounds() {
    let valid = PolicyProvenance::new(7, [0x71; 32], vec!["redact-password".to_owned()])
        .expect("valid durable provenance");
    assert_eq!(valid.generation(), 7);
    assert_eq!(valid.digest(), [0x71; 32]);
    assert_eq!(valid.applied_rules(), &["redact-password"]);

    assert!(PolicyProvenance::new(0, [0x71; 32], Vec::new()).is_err());
    assert!(PolicyProvenance::new(1, [0; 32], Vec::new()).is_err());
    assert!(PolicyProvenance::new(1, [0x71; 32], vec![String::new()]).is_err());
    assert!(
        PolicyProvenance::new(
            1,
            [0x71; 32],
            vec!["x".repeat(PolicyProvenance::MAX_RULE_ID_BYTES + 1)],
        )
        .is_err()
    );
    assert!(
        PolicyProvenance::new(
            1,
            [0x71; 32],
            vec!["rule".to_owned(); PolicyProvenance::MAX_APPLIED_RULES + 1],
        )
        .is_err()
    );
}

#[test]
fn borrowed_validation_matches_owned_reconstruction_without_retaining_values() {
    let rules = ["first", "second"];
    PolicyProvenance::validate_parts(9, [0x79; 32], rules).expect("borrowed valid provenance");
    let failure = PolicyProvenance::validate_parts(9, [0x79; 32], ["", "secret-canary"])
        .expect_err("empty borrowed rule identity");
    assert_eq!(failure.to_string(), "Policy Provenance validation failed");
}
