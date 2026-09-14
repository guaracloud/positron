use positron_policy::{
    PolicyPreview, PolicyPreviewCandidate, PolicyPreviewFailure, PolicyPreviewOutcome,
    PolicyPreviewPolicy, PolicyPreviewSemanticChange,
};

#[test]
fn preview_rejects_oversized_or_secret_bearing_external_candidates_before_evaluation() {
    let oversized = PolicyPreviewCandidate::from_json(&vec![b' '; 65_537]);
    assert_eq!(oversized, Err(PolicyPreviewFailure::RequestTooLarge));

    let secret = PolicyPreviewCandidate::from_json(
        br#"{"receiver":"otlp_http_json","signal":"logs","body":"secret-canary","attributes":[]}"#,
    )
    .expect("bounded candidate");
    let result = PolicyPreview::explain_default(secret).expect("redacted explanation");
    assert!(!result.rendered().contains("secret-canary"));
}

#[test]
fn external_reject_body_rule_compiles_and_rejects_a_matching_fixture() {
    let policy = PolicyPreviewPolicy::from_json(
        br#"{"generation":2,"rules":[{"id":"reject-secret","predicates":[{"body_exact_text":"secret-canary"}],"action":"reject"}]}"#,
    )
    .expect("bounded supported rule");
    let fixture = PolicyPreviewCandidate::from_json(
        br#"{"receiver":"otlp_http_json","signal":"logs","body":"secret-canary","attributes":[]}"#,
    )
    .expect("fixture");
    assert_eq!(
        PolicyPreview::test(&policy, fixture)
            .expect("preview")
            .outcome(),
        PolicyPreviewOutcome::Rejected
    );
}

#[test]
fn preview_compiles_full_release_1_grammar_and_applies_log_transformations_without_echoing_values()
{
    let policy = PolicyPreviewPolicy::from_json(
        br#"{
          "generation":7,
          "rules":[
            {"id":"redact-otlp-secret","predicates":[
              {"signal_store":"logs"}, {"receiver":"otlp_grpc"},
              {"attribute_exists":{"namespace":"record","key":"secret"}}
            ],"action":{"redact":{"attribute":{"namespace":"record","key":"secret"}}}},
            {"id":"truncate-severe-body","predicates":[
              {"log_severity":17}, {"service_identity":"checkout"},
              {"body_exact_text":"very-private-body"}
            ],"action":{"truncate_bytes":{"target":"body","limit":4}}}
          ]
        }"#,
    )
    .expect("complete supported policy");
    let validation = policy.validation();
    assert_eq!(validation.generation(), 7);
    assert_eq!(validation.rule_count(), 2);

    let fixture = PolicyPreviewCandidate::from_json(
        br#"{
          "receiver":"otlp_grpc", "signal":"logs", "body":"very-private-body", "severity":17,
          "attributes":[
            {"namespace":"resource","key":"service.name","occurrences":["checkout"]},
            {"namespace":"record","key":"secret","occurrences":["do-not-echo"]}
          ]
        }"#,
    )
    .expect("log fixture");

    let preview = PolicyPreview::test(&policy, fixture).expect("nonmutating preview");
    assert_eq!(preview.outcome(), PolicyPreviewOutcome::Accepted);
    assert_eq!(preview.applied_rule_count(), 2);
    let explanation = PolicyPreview::explain(&policy, preview).expect("redacted explanation");
    assert!(explanation.rendered().contains("action=redact"));
    assert!(!explanation.rendered().contains("very-private-body"));
    assert!(!explanation.rendered().contains("do-not-echo"));
}

#[test]
fn preview_supports_trace_rules_and_semantic_redacted_diffs() {
    let old = PolicyPreviewPolicy::from_json(
        br#"{"generation":3,"rules":[{"id":"trace-secret","predicates":[{"signal_store":"traces"},{"receiver":"loki_otlp_json"},{"attribute_type":{"path":{"namespace":"record","key":"secret"},"kind":"string"}}],"action":{"remove":{"attribute":{"namespace":"record","key":"secret"}}}}]}"#,
    )
    .expect("trace policy");
    let revised = PolicyPreviewPolicy::from_json(
        br#"{"generation":4,"rules":[{"id":"trace-secret","predicates":[{"signal_store":"traces"},{"receiver":"loki_otlp_json"},{"attribute_type":{"path":{"namespace":"record","key":"secret"},"kind":"string"}}],"action":{"redact":{"attribute":{"namespace":"record","key":"secret"}}}}]}"#,
    )
    .expect("revised policy");
    let fixture = PolicyPreviewCandidate::from_json(
        br#"{"receiver":"loki_otlp_json","signal":"traces","attributes":[{"namespace":"record","key":"secret","occurrences":["canary"]}]}"#,
    )
    .expect("trace fixture");
    let result = PolicyPreview::test(&old, fixture).expect("trace preview");
    assert_eq!(result.outcome(), PolicyPreviewOutcome::Accepted);
    assert_eq!(result.applied_rule_count(), 1);

    let diff = PolicyPreview::diff(&old, &revised);
    assert!(diff.changes().iter().any(|change| matches!(
        change,
        PolicyPreviewSemanticChange::GenerationChanged { from: 3, to: 4 }
    )));
    assert!(diff.changes().iter().any(|change| matches!(
        change,
        PolicyPreviewSemanticChange::RuleActionChanged {
            from: "remove",
            to: "redact"
        }
    )));
    assert!(!format!("{diff:?}").contains("canary"));
}

#[test]
fn preview_rejects_unknown_or_intrinsic_candidate_forms_before_evaluation() {
    let unknown_receiver = PolicyPreviewCandidate::from_json(
        br#"{"receiver":"unknown","signal":"logs","attributes":[]}"#,
    );
    assert_eq!(
        unknown_receiver,
        Err(PolicyPreviewFailure::MalformedCandidate)
    );

    let trace_body = PolicyPreviewCandidate::from_json(
        br#"{"receiver":"otlp_grpc","signal":"traces","body":"forbidden","attributes":[]}"#,
    );
    assert_eq!(trace_body, Err(PolicyPreviewFailure::MalformedCandidate));

    let intrinsic_target = PolicyPreviewPolicy::from_json(
        br#"{"generation":1,"rules":[{"id":"forbidden","predicates":[],"action":{"redact":{"attribute":{"namespace":"resource","key":"service.name"}}}}]}"#,
    );
    assert!(matches!(
        intrinsic_target,
        Err(PolicyPreviewFailure::InvalidPolicy)
    ));

    let unsafe_rule_identity = PolicyPreviewPolicy::from_json(
        br#"{"generation":1,"rules":[{"id":"secret_canary","predicates":[],"action":"accept"}]}"#,
    );
    assert!(matches!(
        unsafe_rule_identity,
        Err(PolicyPreviewFailure::InvalidPolicy)
    ));
}

#[test]
fn preview_parses_remaining_release_1_actions_receivers_and_bounded_nested_values() {
    let policy = PolicyPreviewPolicy::from_json(
        br#"{
          "generation":9,
          "rules":[
            {"id":"accept-http-protobuf","predicates":[{"receiver":"otlp_http_protobuf"}],"action":{"accept":true}},
            {"id":"remove-http-json","predicates":[{"receiver":"otlp_http_json"}],"action":{"remove":{"attribute":{"namespace":"stream","key":"temp"}}}},
            {"id":"truncate-elements","predicates":[
              {"receiver":"loki_push_json"},
              {"attribute_exists":{"namespace":"record","key":"values","segments":[{"array_index":0}]}}
            ],"action":{"truncate_elements":{"target":{"attribute":{"namespace":"record","key":"values"}},"limit":1}}},
            {"id":"push-protobuf","predicates":[{"receiver":"loki_push_protobuf"}],"action":"reject"},
            {"id":"loki-protobuf","predicates":[{"receiver":"loki_otlp_protobuf"}],"action":"reject"},
            {"id":"loki-json","predicates":[{"receiver":"loki_otlp_json"}],"action":"reject"}
          ]
        }"#,
    )
    .expect("all remaining grammar forms");
    let fixture = PolicyPreviewCandidate::from_json(
        br#"{
          "receiver":"loki_push_json","signal":"logs","attributes":[
            {"namespace":"record","key":"values","occurrences":[{"array":["one","two"]}]},
            {"namespace":"stream","key":"temp","occurrences":[{"bytes":[1,2,3]}]}
          ]
        }"#,
    )
    .expect("bounded nested fixture");
    let result = PolicyPreview::test(&policy, fixture).expect("fixture evaluation");
    assert_eq!(result.outcome(), PolicyPreviewOutcome::Accepted);
    assert_eq!(result.applied_rule_count(), 1);
}
