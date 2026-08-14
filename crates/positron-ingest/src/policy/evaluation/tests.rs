use positron_domain::value::{
    AttributeValueKind, CandidateAttributeValue, CandidateKeyValue, PolicyValueMarker,
};

use super::{
    PolicyOccurrence, PolicyPathSegment, Transformation, candidate_kind, candidate_text, selected,
    transform_value, truncate_bytes, truncate_elements, value_path_exists, value_path_has_type,
};

#[test]
fn native_type_matching_preserves_every_value_kind_through_truncation_evidence() {
    let cases = [
        (CandidateAttributeValue::null(), AttributeValueKind::Null),
        (
            CandidateAttributeValue::boolean(true),
            AttributeValueKind::Boolean,
        ),
        (
            CandidateAttributeValue::signed_integer(7),
            AttributeValueKind::SignedInteger,
        ),
        (
            CandidateAttributeValue::floating_point_bits(7),
            AttributeValueKind::FloatingPoint,
        ),
        (
            CandidateAttributeValue::string("value".to_owned()),
            AttributeValueKind::String,
        ),
        (
            CandidateAttributeValue::bytes(vec![1]),
            AttributeValueKind::Bytes,
        ),
        (
            CandidateAttributeValue::array(Vec::new()),
            AttributeValueKind::Array,
        ),
        (
            CandidateAttributeValue::key_value_list(Vec::new()),
            AttributeValueKind::KeyValueList,
        ),
        (
            CandidateAttributeValue::policy_marker(PolicyValueMarker::Removed),
            AttributeValueKind::PolicyMarker,
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(candidate_kind(&value), expected);
        assert_eq!(
            candidate_kind(&CandidateAttributeValue::truncated(value)),
            expected
        );
    }
}

#[test]
fn nested_lookup_and_mutation_follow_arrays_duplicate_keys_and_truncated_wrappers() {
    let mut value =
        CandidateAttributeValue::truncated(CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "token".to_owned(),
                CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::string("keep".to_owned()),
                    CandidateAttributeValue::string("first".to_owned()),
                ]),
            ),
            CandidateKeyValue::new(
                "token".to_owned(),
                CandidateAttributeValue::truncated(CandidateAttributeValue::array(vec![
                    CandidateAttributeValue::string("keep".to_owned()),
                    CandidateAttributeValue::string("second".to_owned()),
                ])),
            ),
        ]));
    let segments = [
        PolicyPathSegment::Key("token".to_owned()),
        PolicyPathSegment::ArrayIndex(1),
    ];

    assert!(value_path_exists(&value, &segments));
    assert!(value_path_has_type(
        &value,
        &segments,
        AttributeValueKind::String
    ));
    assert!(!value_path_has_type(
        &value,
        &segments,
        AttributeValueKind::Bytes
    ));
    assert!(!value_path_exists(
        &value,
        &[PolicyPathSegment::Key("missing".to_owned())]
    ));
    assert!(!value_path_exists(
        &value,
        &[
            PolicyPathSegment::Key("token".to_owned()),
            PolicyPathSegment::ArrayIndex(9),
        ]
    ));
    assert!(transform_value(
        &mut value,
        &segments,
        Transformation::Redact
    ));

    let CandidateAttributeValue::Truncated(value) = value else {
        panic!("outer truncation evidence was lost");
    };
    let CandidateAttributeValue::KeyValueList(entries) = *value else {
        panic!("nested list was lost");
    };
    for entry in entries {
        let value = match entry.value() {
            CandidateAttributeValue::Array(values) => &values[1],
            CandidateAttributeValue::Truncated(value) => match value.as_ref() {
                CandidateAttributeValue::Array(values) => &values[1],
                _ => panic!("nested array was lost"),
            },
            _ => panic!("nested array was lost"),
        };
        assert_eq!(
            value,
            &CandidateAttributeValue::policy_marker(PolicyValueMarker::Redacted)
        );
    }
}

#[test]
fn truncation_is_typed_for_bytes_and_key_value_lists_and_noops_for_wrong_kinds() {
    let mut bytes = CandidateAttributeValue::bytes(vec![1, 2, 3]);
    assert!(truncate_bytes(&mut bytes, 2));
    assert!(!truncate_bytes(&mut bytes, 2));

    let mut entries = CandidateAttributeValue::key_value_list(vec![
        CandidateKeyValue::new("a".to_owned(), CandidateAttributeValue::null()),
        CandidateKeyValue::new("b".to_owned(), CandidateAttributeValue::null()),
    ]);
    assert!(truncate_elements(&mut entries, 1));
    assert!(!truncate_elements(&mut entries, 1));

    let mut scalar = CandidateAttributeValue::boolean(false);
    assert!(!truncate_bytes(&mut scalar, 0));
    assert!(!truncate_elements(&mut scalar, 0));
    assert!(!transform_value(
        &mut scalar,
        &[PolicyPathSegment::Key("missing".to_owned())],
        Transformation::Remove
    ));
    assert!(!transform_value(
        &mut scalar,
        &[PolicyPathSegment::ArrayIndex(0)],
        Transformation::Remove
    ));
}

#[test]
fn body_text_and_occurrence_selection_are_exact_and_source_ordered() {
    let text = CandidateAttributeValue::string("body".to_owned());
    let wrapped = CandidateAttributeValue::truncated(text.clone());
    assert_eq!(candidate_text(&text), Some("body"));
    assert_eq!(candidate_text(&wrapped), Some("body"));
    assert_eq!(candidate_text(&CandidateAttributeValue::null()), None);

    let values = [
        CandidateAttributeValue::signed_integer(1),
        CandidateAttributeValue::signed_integer(2),
    ];
    assert_eq!(selected(&values, PolicyOccurrence::All).count(), 2);
    assert_eq!(
        selected(&values, PolicyOccurrence::Index(1)).collect::<Vec<_>>(),
        vec![&values[1]]
    );
    assert_eq!(selected(&values, PolicyOccurrence::Index(9)).count(), 0);
}
