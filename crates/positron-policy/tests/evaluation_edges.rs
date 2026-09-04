use positron_domain::routing::SignalKind;
use positron_domain::value::{
    AttributeNamespace, AttributeValueKind, CandidateAttributeValue, CandidateKeyValue,
    MarkerAction,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyAction,
    PolicyAttributePath, PolicyEvaluation, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget,
};

#[test]
fn nested_repeated_mutations_and_every_native_type_are_bounded_and_ordered() {
    let types = vec![
        CandidateAttributeValue::null(),
        CandidateAttributeValue::boolean(true),
        CandidateAttributeValue::signed_integer(-1),
        CandidateAttributeValue::floating_point_bits(1_f64.to_bits()),
        CandidateAttributeValue::string("text".into()),
        CandidateAttributeValue::bytes(vec![1]),
        CandidateAttributeValue::array(Vec::new()),
        CandidateAttributeValue::key_value_list(Vec::new()),
    ];
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        vec![
            attribute("types", types),
            attribute(
                "payload",
                vec![CandidateAttributeValue::key_value_list(vec![
                    CandidateKeyValue::new(
                        "child".into(),
                        CandidateAttributeValue::array(vec![CandidateAttributeValue::string(
                            "secret".into(),
                        )]),
                    ),
                    CandidateKeyValue::new(
                        "child".into(),
                        CandidateAttributeValue::array(vec![CandidateAttributeValue::string(
                            "second".into(),
                        )]),
                    ),
                ])],
            ),
            attribute(
                "repeated",
                vec![
                    CandidateAttributeValue::string("keep".into()),
                    CandidateAttributeValue::string("remove".into()),
                ],
            ),
            attribute(
                "array",
                vec![CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::signed_integer(1),
                    CandidateAttributeValue::signed_integer(2),
                ])],
            ),
            attribute("bytes", vec![CandidateAttributeValue::bytes(vec![1, 2, 3])]),
            attribute(
                "list",
                vec![CandidateAttributeValue::key_value_list(vec![
                    CandidateKeyValue::new("a".into(), CandidateAttributeValue::null()),
                    CandidateKeyValue::new("b".into(), CandidateAttributeValue::null()),
                ])],
            ),
            attribute("null", vec![CandidateAttributeValue::null()]),
        ],
        LogMetadata::empty(),
    );
    let missing = path("missing");
    let mut rules = Vec::new();
    for (index, kind) in [
        AttributeValueKind::Null,
        AttributeValueKind::Boolean,
        AttributeValueKind::SignedInteger,
        AttributeValueKind::FloatingPoint,
        AttributeValueKind::String,
        AttributeValueKind::Bytes,
        AttributeValueKind::Array,
        AttributeValueKind::KeyValueList,
    ]
    .into_iter()
    .enumerate()
    {
        rules.push(
            PolicyRule::new(
                format!("type-{index}"),
                vec![PolicyPredicate::attribute_type(
                    path("types").at_occurrence(u16::try_from(index).expect("small index")),
                    kind,
                )],
                PolicyAction::Redact(PolicyTarget::attribute(missing.clone())),
            )
            .expect("rule"),
        );
    }
    let nested = path("payload")
        .key("child")
        .expect("key")
        .array_index(0)
        .expect("index");
    rules.extend([
        rule(
            "nested",
            nested.clone(),
            PolicyAction::Redact(PolicyTarget::attribute(nested)),
        ),
        rule(
            "remove-occurrence",
            path("repeated").at_occurrence(1),
            PolicyAction::Remove(PolicyTarget::attribute(path("repeated").at_occurrence(1))),
        ),
        rule(
            "remove-array-entry",
            path("array").array_index(0).expect("index"),
            PolicyAction::Remove(PolicyTarget::attribute(
                path("array").array_index(0).expect("index"),
            )),
        ),
        rule(
            "truncate-bytes",
            path("bytes"),
            PolicyAction::TruncateBytes(PolicyTarget::attribute(path("bytes")), 2),
        ),
        rule(
            "truncate-list",
            path("list"),
            PolicyAction::TruncateElements(PolicyTarget::attribute(path("list")), 1),
        ),
        rule(
            "redact-null",
            path("null"),
            PolicyAction::Redact(PolicyTarget::attribute(path("null"))),
        ),
        PolicyRule::new(
            "remove-missing",
            vec![PolicyPredicate::log_severity(0)],
            PolicyAction::Remove(PolicyTarget::attribute(missing)),
        )
        .expect("rule"),
    ]);
    let policy = IngestPolicy::compile(5, rules).expect("bounded policy");
    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("bounded evaluation")
    else {
        panic!("non-terminal policy rejected")
    };
    let (_, _, _, attributes, _, provenance) = record.into_parts();

    assert_eq!(occurrences(&attributes, "repeated").len(), 2);
    assert!(matches!(
        occurrences(&attributes, "repeated")[1],
        CandidateAttributeValue::Marker(marker)
            if marker.action() == MarkerAction::Removed
                && marker.original_kind() == AttributeValueKind::String
    ));
    assert!(matches!(
        occurrences(&attributes, "bytes"),
        [CandidateAttributeValue::Truncated { value, action }]
            if *action == MarkerAction::TruncatedBytes
                && matches!(value.as_ref(), CandidateAttributeValue::Bytes(bytes) if bytes == &[1, 2])
    ));
    assert!(matches!(
        occurrences(&attributes, "list"),
        [CandidateAttributeValue::Truncated { value, action }]
            if *action == MarkerAction::TruncatedElements
                && matches!(value.as_ref(), CandidateAttributeValue::KeyValueList(entries) if entries.len() == 1)
    ));
    assert!(matches!(
        occurrences(&attributes, "array"),
        [CandidateAttributeValue::Array(values)]
            if values.len() == 2
                && matches!(values[0], CandidateAttributeValue::Marker(marker)
                    if marker.action() == MarkerAction::Removed)
    ));
    let CandidateAttributeValue::KeyValueList(entries) = &occurrences(&attributes, "payload")[0]
    else {
        panic!("payload shape changed")
    };
    assert!(entries.iter().all(|entry| matches!(
        entry.value(),
        CandidateAttributeValue::Array(values)
            if matches!(values.as_slice(), [CandidateAttributeValue::Marker(marker)]
                if marker.action() == MarkerAction::Redacted)
    )));
    assert_eq!(
        provenance.applied_rules(),
        &[
            "nested",
            "remove-occurrence",
            "remove-array-entry",
            "truncate-bytes",
            "truncate-list",
            "redact-null"
        ]
    );
}

fn attribute(key: &str, occurrences: Vec<CandidateAttributeValue>) -> NativeLogAttribute {
    NativeLogAttribute::new(AttributeNamespace::Record, key.into(), occurrences)
}

fn path(key: &str) -> PolicyAttributePath {
    PolicyAttributePath::new(AttributeNamespace::Record, key).expect("path")
}

fn rule(id: &str, path: PolicyAttributePath, action: PolicyAction) -> PolicyRule {
    PolicyRule::new(id, vec![PolicyPredicate::attribute_exists(path)], action).expect("rule")
}

fn occurrences<'a>(
    attributes: &'a [NativeLogAttribute],
    key: &str,
) -> &'a [CandidateAttributeValue] {
    attributes
        .iter()
        .find(|attribute| attribute.key() == key)
        .expect("attribute")
        .occurrences()
}

#[test]
fn policy_rejects_producer_markers_but_emits_typed_redaction_markers() {
    let forged = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::redaction_marker(
            AttributeValueKind::String,
            MarkerAction::Redacted,
        )),
        Vec::new(),
        LogMetadata::empty(),
    );
    let preserving = IngestPolicy::preserving(6).expect("preserving policy");
    assert!(
        preserving
            .evaluate(forged, PolicyReceiver::OtlpGrpc)
            .is_err()
    );

    let path = path("secret");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        None,
        vec![attribute(
            "secret",
            vec![CandidateAttributeValue::string("source".to_owned())],
        )],
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        7,
        vec![rule(
            "redact",
            path.clone(),
            PolicyAction::Redact(PolicyTarget::attribute(path)),
        )],
    )
    .expect("policy");
    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("record rejected")
    };
    let (_, _, _, attributes, _, _) = record.into_parts();
    let value = attributes[0].occurrences()[0].clone();
    assert_eq!(value.marker_action(), Some(MarkerAction::Redacted));
    assert_eq!(
        value.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert!(value.as_str().is_none());
}

#[test]
fn policy_rejects_markers_hidden_in_attribute_collections_before_rules_run() {
    let forged = NativeLogCandidate::new(
        None,
        None,
        None,
        vec![attribute(
            "payload",
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "nested".to_owned(),
                    CandidateAttributeValue::array(vec![
                        CandidateAttributeValue::redaction_marker(
                            AttributeValueKind::String,
                            MarkerAction::Removed,
                        ),
                    ]),
                ),
            ])],
        )],
        LogMetadata::empty(),
    );

    let preserving = IngestPolicy::preserving(11).expect("preserving policy");
    assert_eq!(
        preserving.evaluate(forged, PolicyReceiver::OtlpHttpJson),
        Err(positron_policy::PolicyEvaluationFailure::UntrustedMarker)
    );
}

#[test]
fn policy_truncation_keeps_sanitized_native_value_and_action_evidence() {
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("source-value".to_owned())),
        Vec::new(),
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        8,
        vec![
            PolicyRule::new(
                "truncate",
                vec![PolicyPredicate::body_exact_text("source-value").expect("predicate")],
                PolicyAction::TruncateBytes(PolicyTarget::body(), 6),
            )
            .expect("rule"),
        ],
    )
    .expect("policy");
    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("record rejected")
    };
    let (_, _, body, _, _, _) = record.into_parts();
    let body = body.expect("body");
    assert_eq!(body.as_str(), Some("source"));
    assert_eq!(body.truncation_action(), Some(MarkerAction::TruncatedBytes));
}

#[test]
fn policy_evaluation_preserves_nested_truncation_paths_and_noop_boundaries() {
    let nested = path("nested");
    let nested_child = nested
        .clone()
        .key("child")
        .expect("child path")
        .array_index(1)
        .expect("array index path");
    let missing = path("missing");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("aéz".to_owned())),
        vec![
            attribute(
                "nested",
                vec![CandidateAttributeValue::key_value_list(vec![
                    CandidateKeyValue::new(
                        "child".to_owned(),
                        CandidateAttributeValue::array(vec![
                            CandidateAttributeValue::string("keep".to_owned()),
                            CandidateAttributeValue::string("secret".to_owned()),
                        ]),
                    ),
                    CandidateKeyValue::new(
                        "discarded".to_owned(),
                        CandidateAttributeValue::string("source".to_owned()),
                    ),
                ])],
            ),
            attribute(
                "array",
                vec![CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::signed_integer(1),
                    CandidateAttributeValue::signed_integer(2),
                ])],
            ),
            attribute("bytes", vec![CandidateAttributeValue::bytes(vec![1, 2, 3])]),
            attribute("boolean", vec![CandidateAttributeValue::boolean(true)]),
        ],
        LogMetadata::empty(),
    );
    let policy = IngestPolicy::compile(
        10,
        vec![
            PolicyRule::new(
                "truncate-body",
                vec![PolicyPredicate::signal_store(SignalKind::Logs)],
                PolicyAction::TruncateBytes(PolicyTarget::body(), 2),
            )
            .expect("body truncation rule"),
            PolicyRule::new(
                "check-truncated-body",
                vec![PolicyPredicate::body_exact_text("a").expect("body predicate")],
                PolicyAction::Remove(PolicyTarget::attribute(missing.clone())),
            )
            .expect("body query rule"),
            PolicyRule::new(
                "truncate-nested",
                vec![PolicyPredicate::attribute_exists(nested.clone())],
                PolicyAction::TruncateElements(PolicyTarget::attribute(nested.clone()), 1),
            )
            .expect("nested truncation rule"),
            PolicyRule::new(
                "query-truncated-child",
                vec![PolicyPredicate::attribute_type(
                    nested_child.clone(),
                    AttributeValueKind::String,
                )],
                PolicyAction::Remove(PolicyTarget::attribute(missing.clone())),
            )
            .expect("nested type rule"),
            PolicyRule::new(
                "redact-nested-child",
                vec![PolicyPredicate::attribute_exists(nested_child.clone())],
                PolicyAction::Redact(PolicyTarget::attribute(nested_child.clone())),
            )
            .expect("nested redaction rule"),
            PolicyRule::new(
                "redact-marker-again",
                vec![PolicyPredicate::attribute_exists(nested_child.clone())],
                PolicyAction::Redact(PolicyTarget::attribute(nested_child.clone())),
            )
            .expect("marker no-op rule"),
            PolicyRule::new(
                "query-marker-as-string",
                vec![PolicyPredicate::attribute_type(
                    nested_child,
                    AttributeValueKind::String,
                )],
                PolicyAction::Remove(PolicyTarget::attribute(missing.clone())),
            )
            .expect("marker type rule"),
            PolicyRule::new(
                "truncate-array",
                vec![PolicyPredicate::attribute_exists(path("array"))],
                PolicyAction::TruncateElements(PolicyTarget::attribute(path("array")), 1),
            )
            .expect("array truncation rule"),
            PolicyRule::new(
                "truncate-bytes",
                vec![PolicyPredicate::attribute_exists(path("bytes"))],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(path("bytes")), 2),
            )
            .expect("byte truncation rule"),
            PolicyRule::new(
                "bytes-noop-on-boolean",
                vec![PolicyPredicate::attribute_exists(path("boolean"))],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(path("boolean")), 1),
            )
            .expect("scalar byte no-op rule"),
        ],
    )
    .expect("policy compiles");

    let PolicyEvaluation::Accepted(record) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("policy evaluation succeeds")
    else {
        panic!("policy unexpectedly rejected candidate");
    };
    let (_, _, body, attributes, _, provenance) = record.into_parts();
    let body = body.expect("body remains present");
    assert_eq!(body.as_str(), Some("a"));
    assert_eq!(body.truncation_action(), Some(MarkerAction::TruncatedBytes));

    let nested = occurrences(&attributes, "nested")[0].clone();
    let CandidateAttributeValue::Truncated { value, action } = nested else {
        panic!("nested value was not truncated");
    };
    assert_eq!(action, MarkerAction::TruncatedElements);
    let CandidateAttributeValue::KeyValueList(entries) = value.as_ref() else {
        panic!("nested value lost its key/value shape");
    };
    let child = entries[0].value();
    assert!(matches!(
        child,
        CandidateAttributeValue::Array(values)
            if matches!(values.get(1), Some(CandidateAttributeValue::Marker(marker))
            if marker.action() == MarkerAction::Redacted
                && marker.original_kind() == AttributeValueKind::String)
    ));
    let CandidateAttributeValue::Truncated { value, action } =
        &occurrences(&attributes, "array")[0]
    else {
        panic!("array value was not truncated");
    };
    assert_eq!(*action, MarkerAction::TruncatedElements);
    assert!(matches!(
        value.as_ref(),
        CandidateAttributeValue::Array(values)
            if matches!(values.as_slice(), [CandidateAttributeValue::SignedInteger(1)])
    ));
    assert_eq!(
        occurrences(&attributes, "bytes")[0],
        CandidateAttributeValue::Truncated {
            value: Box::new(CandidateAttributeValue::Bytes(vec![1, 2])),
            action: MarkerAction::TruncatedBytes,
        }
    );
    assert_eq!(
        &occurrences(&attributes, "boolean")[0],
        &CandidateAttributeValue::Boolean(true)
    );
    assert_eq!(
        provenance.applied_rules(),
        &[
            "truncate-body",
            "truncate-nested",
            "redact-nested-child",
            "truncate-array",
            "truncate-bytes"
        ]
    );
}
