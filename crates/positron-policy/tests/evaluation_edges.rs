use positron_domain::value::{
    AttributeNamespace, AttributeValueKind, CandidateAttributeValue, CandidateKeyValue,
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

    assert_eq!(occurrences(&attributes, "repeated").len(), 1);
    assert!(matches!(
        occurrences(&attributes, "bytes"),
        [CandidateAttributeValue::Bytes(bytes)] if bytes == &[1, 2]
    ));
    assert!(matches!(
        occurrences(&attributes, "list"),
        [CandidateAttributeValue::KeyValueList(entries)] if entries.len() == 1
    ));
    assert!(matches!(
        occurrences(&attributes, "array"),
        [CandidateAttributeValue::Array(values)] if values.len() == 1
    ));
    let CandidateAttributeValue::KeyValueList(entries) = &occurrences(&attributes, "payload")[0]
    else {
        panic!("payload shape changed")
    };
    assert!(entries.iter().all(|entry| matches!(
        entry.value(),
        CandidateAttributeValue::Array(values)
            if matches!(values.as_slice(), [CandidateAttributeValue::Null])
    )));
    assert_eq!(
        provenance.applied_rules(),
        &[
            "nested",
            "remove-occurrence",
            "remove-array-entry",
            "truncate-bytes",
            "truncate-list"
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
