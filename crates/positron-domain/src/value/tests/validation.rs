use super::*;

#[test]
fn empty_attribute_key_is_rejected_at_the_public_validation_boundary() {
    let result = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        String::new(),
        vec![CandidateAttributeValue::boolean(true)],
    )
    .validate(profile());

    assert!(
        result.is_err(),
        "an attribute key must contain at least one byte"
    );
}

#[test]
fn one_profile_applies_distinct_attribute_and_log_body_byte_limits() {
    let profile = profile_with_value_and_body_bytes(4, 8);
    let attribute = CandidateAttributeValue::string("12345".to_owned()).validate_attribute(profile);
    let body = CandidateAttributeValue::string("12345678".to_owned()).validate_log_body(profile);

    assert!(
        attribute.is_err(),
        "individual attribute values stop at four bytes"
    );
    let body = body.expect("the same profile permits an eight-byte log body");
    assert_eq!(body.as_str(), Some("12345678"));
}

#[test]
fn key_value_lists_are_never_coerced_into_arrays() {
    let value = CandidateAttributeValue::key_value_list(vec![])
        .validate_attribute(profile())
        .expect("empty key/value list is a valid typed collection");

    assert_eq!(value.kind(), AttributeValueKind::KeyValueList);
    assert!(value.array_entry(0).is_none());
}

#[test]
fn owned_scalar_transfer_leaves_structural_values_structural() {
    let value = CandidateAttributeValue::array(vec![])
        .validate_attribute(profile())
        .expect("empty array is a valid typed collection");
    assert!(value.into_scalar().is_none());
}

#[test]
fn configured_system_limits_cannot_raise_the_release_one_safe_maximum() {
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let raised_request = RequestLimits::new(
        ByteLimit::new(maximum.request().compressed_bytes().value() + 1)
            .expect("raised fixture remains nonzero"),
        maximum.request().decompressed_bytes(),
        maximum.request().records(),
        maximum.request().aggregate_attributes(),
    );
    let raised = ValueLimitSet::new(raised_request, maximum.record(), maximum.dynamic_value());

    assert!(
        ValueLimitProfileCandidate::new(raised, None)
            .validate()
            .is_err(),
        "configured system limits cannot exceed the compiled safe maximum"
    );
}

#[test]
fn aggregate_collection_bytes_accept_exact_and_reject_nested_over_limit_values() {
    let profile = profile_with_value_and_body_bytes(4, 8);
    let exact =
        CandidateAttributeValue::array(vec![CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "first".to_owned(),
                CandidateAttributeValue::string("12".to_owned()),
            ),
            CandidateKeyValue::new(
                "second".to_owned(),
                CandidateAttributeValue::string("34".to_owned()),
            ),
        ])])
        .validate_attribute(profile)
        .expect("two nested two-byte values are the exact aggregate boundary");
    assert_eq!(exact.kind(), AttributeValueKind::Array);

    let over = CandidateAttributeValue::array(vec![CandidateAttributeValue::key_value_list(vec![
        CandidateKeyValue::new(
            "first".to_owned(),
            CandidateAttributeValue::string("12".to_owned()),
        ),
        CandidateKeyValue::new(
            "second".to_owned(),
            CandidateAttributeValue::string("345".to_owned()),
        ),
    ])])
    .validate_attribute(profile);
    assert!(
        over.is_err(),
        "nested collection totals cannot exceed the individual-value byte limit"
    );
}

#[test]
fn policy_markers_and_sanitized_values_keep_their_public_native_contract() {
    let profile = super::profile_with_value_and_body_bytes(64, 64);
    let candidate_marker = CandidateAttributeValue::redaction_marker(
        AttributeValueKind::String,
        crate::value::MarkerAction::Redacted,
    );
    assert_eq!(
        candidate_marker.marker_action(),
        Some(crate::value::MarkerAction::Redacted)
    );
    assert_eq!(
        candidate_marker.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert_eq!(candidate_marker.truncation_action(), None);
    assert_eq!(candidate_marker.as_str(), None);
    assert!(candidate_marker.contains_policy_marker());
    let candidate_truncated = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("sanitized".to_owned()),
        crate::value::MarkerAction::TruncatedBytes,
    );
    assert_eq!(candidate_truncated.marker_action(), None);
    assert_eq!(candidate_truncated.marker_original_kind(), None);
    assert_eq!(
        candidate_truncated.truncation_action(),
        Some(crate::value::MarkerAction::TruncatedBytes)
    );
    assert_eq!(candidate_truncated.as_str(), Some("sanitized"));
    assert!(candidate_truncated.contains_policy_marker());

    let marker = CandidateAttributeValue::redaction_marker(
        AttributeValueKind::String,
        crate::value::MarkerAction::Redacted,
    )
    .validate_attribute(profile)
    .expect("a policy marker has no source payload to exceed the value bound");

    assert!(marker.is_marker());
    assert_eq!(marker.kind(), AttributeValueKind::Marker);
    assert_eq!(
        marker.marker_action(),
        Some(crate::value::MarkerAction::Redacted)
    );
    assert_eq!(
        marker.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert_eq!(marker.truncation_action(), None);
    assert_eq!(marker.truncated_value(), None);
    assert!(marker.contains_marker());
    assert!(!marker.is_null());
    assert_eq!(marker.as_signed_integer(), None);
    assert_eq!(marker.as_boolean(), None);
    assert_eq!(marker.as_floating_point_bits(), None);
    assert_eq!(marker.as_str(), None);
    assert_eq!(marker.as_bytes(), None);
    assert_eq!(marker.array_len(), None);
    assert_eq!(marker.array_entry(0), None);
    assert_eq!(marker.key_value_list_len(), None);
    assert_eq!(marker.key_value_entry(0), None);
    assert_eq!(marker.clone().into_scalar(), None);
    assert_eq!(marker.decoded_size_bytes(), Ok(0));
    assert_eq!(marker.canonical_encoded_size_bytes(), Ok(3));
    assert_eq!(marker.comparison_encoded_size_bytes(), Ok(3));
    let mut canonical = Vec::new();
    marker
        .append_canonical_encoding(&mut canonical)
        .expect("marker encoding is bounded");
    assert_eq!(canonical, vec![8, 1, 4]);
    let mut comparison = Vec::new();
    marker
        .append_comparison_encoding(&mut comparison)
        .expect("marker comparison encoding is bounded");
    assert_eq!(comparison, vec![8, 1, 4]);

    let truncated_text = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("sanitized".to_owned()),
        crate::value::MarkerAction::TruncatedBytes,
    )
    .validate_attribute(profile)
    .expect("a same-kind sanitized string remains queryable");
    assert!(!truncated_text.is_marker());
    assert_eq!(truncated_text.kind(), AttributeValueKind::String);
    assert_eq!(truncated_text.marker_action(), None);
    assert_eq!(truncated_text.marker_original_kind(), None);
    assert_eq!(
        truncated_text.truncation_action(),
        Some(crate::value::MarkerAction::TruncatedBytes)
    );
    assert_eq!(
        truncated_text
            .truncated_value()
            .and_then(|value| value.as_str()),
        Some("sanitized")
    );
    assert_eq!(truncated_text.as_str(), Some("sanitized"));
    assert!(!truncated_text.contains_marker());
    assert_eq!(truncated_text.as_bytes(), None);
    assert_eq!(truncated_text.array_len(), None);
    assert_eq!(truncated_text.key_value_list_len(), None);
    assert_eq!(truncated_text.decoded_size_bytes(), Ok(9));
    assert!(truncated_text.canonical_encoded_size_bytes().is_ok());
    assert!(truncated_text.comparison_encoded_size_bytes().is_ok());
    assert!(
        truncated_text.equals_exact(
            &CandidateAttributeValue::string("sanitized".to_owned())
                .validate_attribute(profile)
                .expect("comparison value is bounded")
        )
    );
    assert!(!marker.equals_exact(&marker));
    assert!(truncated_text.equals_exact(&truncated_text));
    let native_text = CandidateAttributeValue::string("sanitized".to_owned())
        .validate_attribute(profile)
        .expect("comparison value is bounded");
    assert!(native_text.equals_exact(&truncated_text));

    let truncated_array = CandidateAttributeValue::truncated(
        CandidateAttributeValue::array(vec![CandidateAttributeValue::redaction_marker(
            AttributeValueKind::String,
            crate::value::MarkerAction::Removed,
        )]),
        crate::value::MarkerAction::TruncatedElements,
    )
    .validate_attribute(profile)
    .expect("a marker leaf inside a retained collection is valid");
    assert_eq!(truncated_array.kind(), AttributeValueKind::Array);
    assert_eq!(truncated_array.array_len(), Some(1));
    assert!(
        truncated_array
            .array_entry(0)
            .is_some_and(|value| value.is_marker())
    );
    assert!(truncated_array.contains_marker());
    assert_eq!(truncated_array.retained_heap_bytes(), Ok(64));

    let truncated_list = CandidateAttributeValue::truncated(
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "nested".to_owned(),
            CandidateAttributeValue::redaction_marker(
                AttributeValueKind::Bytes,
                crate::value::MarkerAction::Redacted,
            ),
        )]),
        crate::value::MarkerAction::TruncatedElements,
    )
    .validate_attribute(profile)
    .expect("a marker leaf inside a retained key/value list is valid");
    assert_eq!(truncated_list.kind(), AttributeValueKind::KeyValueList);
    assert_eq!(truncated_list.key_value_list_len(), Some(1));
    assert_eq!(
        truncated_list
            .key_value_entry(0)
            .and_then(|entry| entry.value().marker_action()),
        Some(crate::value::MarkerAction::Redacted)
    );
    assert!(truncated_list.contains_marker());

    let ordinary_array =
        CandidateAttributeValue::array(vec![CandidateAttributeValue::string("value".to_owned())])
            .validate_attribute(profile)
            .expect("ordinary array validates");
    assert!(ordinary_array.equals_exact(&ordinary_array));
    let ordinary_list = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "key".to_owned(),
        CandidateAttributeValue::string("value".to_owned()),
    )])
    .validate_attribute(profile)
    .expect("ordinary key/value list validates");
    assert!(ordinary_list.equals_exact(&ordinary_list));

    for (kind, tag) in [
        (AttributeValueKind::Null, 0),
        (AttributeValueKind::Boolean, 1),
        (AttributeValueKind::SignedInteger, 2),
        (AttributeValueKind::FloatingPoint, 3),
        (AttributeValueKind::String, 4),
        (AttributeValueKind::Bytes, 5),
        (AttributeValueKind::Array, 6),
        (AttributeValueKind::KeyValueList, 7),
    ] {
        let marker =
            CandidateAttributeValue::redaction_marker(kind, crate::value::MarkerAction::Removed)
                .validate_attribute(profile)
                .expect("every native kind can be represented by a marker");
        let mut encoded = Vec::new();
        marker
            .append_canonical_encoding(&mut encoded)
            .expect("marker encoding is bounded");
        assert_eq!(encoded, vec![8, 0, tag]);
    }
}

#[test]
fn invalid_or_forged_marker_shapes_are_rejected_at_validation_boundary() {
    let profile = super::profile_with_value_and_body_bytes(64, 64);
    let invalid = [
        CandidateAttributeValue::redaction_marker(
            AttributeValueKind::Marker,
            crate::value::MarkerAction::Redacted,
        ),
        CandidateAttributeValue::redaction_marker(
            AttributeValueKind::String,
            crate::value::MarkerAction::TruncatedBytes,
        ),
        CandidateAttributeValue::truncated(
            CandidateAttributeValue::boolean(true),
            crate::value::MarkerAction::TruncatedBytes,
        ),
        CandidateAttributeValue::truncated(
            CandidateAttributeValue::string("text".to_owned()),
            crate::value::MarkerAction::TruncatedElements,
        ),
        CandidateAttributeValue::truncated(
            CandidateAttributeValue::redaction_marker(
                AttributeValueKind::String,
                crate::value::MarkerAction::Redacted,
            ),
            crate::value::MarkerAction::TruncatedBytes,
        ),
        CandidateAttributeValue::truncated(
            CandidateAttributeValue::truncated(
                CandidateAttributeValue::string("text".to_owned()),
                crate::value::MarkerAction::TruncatedBytes,
            ),
            crate::value::MarkerAction::TruncatedBytes,
        ),
    ];

    for candidate in invalid {
        assert!(candidate.validate_shape(profile).is_err());
        assert!(candidate.validate_attribute(profile).is_err());
    }
}

#[test]
fn native_values_have_exact_total_order_and_self_delimiting_encoding() {
    let profile = ValueLimitProfile::release_1_system_maximum();
    let negative_zero = CandidateAttributeValue::floating_point_bits((-0.0_f64).to_bits())
        .validate_log_body(profile)
        .expect("negative zero is a bounded native value");
    let positive_zero = CandidateAttributeValue::floating_point_bits(0.0_f64.to_bits())
        .validate_log_body(profile)
        .expect("positive zero is a bounded native value");
    let first_nan = CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0001)
        .validate_log_body(profile)
        .expect("a NaN payload remains a native value");
    let second_nan = CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0002)
        .validate_log_body(profile)
        .expect("a distinct NaN payload remains a native value");

    assert!(negative_zero < positive_zero);
    assert!(first_nan < second_nan);
    assert_ne!(negative_zero, positive_zero);

    let validated = |candidate: CandidateAttributeValue| {
        candidate
            .validate_log_body(profile)
            .expect("comparison fixture is within the release-one body limit")
    };
    assert_eq!(
        validated(CandidateAttributeValue::null()).cmp(&validated(CandidateAttributeValue::null())),
        std::cmp::Ordering::Equal
    );
    assert!(
        validated(CandidateAttributeValue::boolean(false))
            < validated(CandidateAttributeValue::boolean(true))
    );
    assert!(
        validated(CandidateAttributeValue::signed_integer(1))
            < validated(CandidateAttributeValue::signed_integer(2))
    );
    assert!(
        validated(CandidateAttributeValue::bytes(vec![1]))
            < validated(CandidateAttributeValue::bytes(vec![2]))
    );
    assert!(
        validated(CandidateAttributeValue::array(vec![
            CandidateAttributeValue::boolean(false),
        ])) < validated(CandidateAttributeValue::array(vec![
            CandidateAttributeValue::boolean(true),
        ]))
    );
    let first_key = validated(CandidateAttributeValue::key_value_list(vec![
        CandidateKeyValue::new("a".to_owned(), CandidateAttributeValue::null()),
    ]));
    let second_key = validated(CandidateAttributeValue::key_value_list(vec![
        CandidateKeyValue::new("b".to_owned(), CandidateAttributeValue::null()),
    ]));
    assert!(first_key < second_key);
    assert_eq!(
        first_key
            .key_value_entry(0)
            .expect("first key exists")
            .partial_cmp(second_key.key_value_entry(0).expect("second key exists")),
        Some(std::cmp::Ordering::Less)
    );
    assert!(
        validated(CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new("same".to_owned(), CandidateAttributeValue::boolean(false),),
        ])) < validated(CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new("same".to_owned(), CandidateAttributeValue::boolean(true),),
        ]))
    );

    let value = CandidateAttributeValue::array(vec![
        CandidateAttributeValue::string(String::new()),
        CandidateAttributeValue::bytes(vec![0, 255]),
    ])
    .validate_log_body(profile)
    .expect("fixture is within the release-one body limit");
    let mut encoding = Vec::new();
    value
        .append_canonical_encoding(&mut encoding)
        .expect("a validated value has a bounded canonical encoding");
    assert_eq!(
        encoding,
        vec![
            6, 0, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            255,
        ]
    );
    assert_eq!(value.canonical_encoded_size_bytes(), Ok(29));
    assert_eq!(value.retained_heap_bytes(), Ok(130));
}

#[test]
fn native_comparison_encoding_has_exactly_the_canonical_total_order() {
    let profile = ValueLimitProfile::release_1_system_maximum();
    let values = [
        CandidateAttributeValue::null(),
        CandidateAttributeValue::boolean(false),
        CandidateAttributeValue::boolean(true),
        CandidateAttributeValue::signed_integer(i64::MIN),
        CandidateAttributeValue::signed_integer(-1),
        CandidateAttributeValue::signed_integer(0),
        CandidateAttributeValue::signed_integer(i64::MAX),
        CandidateAttributeValue::floating_point_bits(0xfff8_0000_0000_0002),
        CandidateAttributeValue::floating_point_bits(0xfff8_0000_0000_0001),
        CandidateAttributeValue::floating_point_bits(f64::NEG_INFINITY.to_bits()),
        CandidateAttributeValue::floating_point_bits((-0.0_f64).to_bits()),
        CandidateAttributeValue::floating_point_bits(0.0_f64.to_bits()),
        CandidateAttributeValue::floating_point_bits(f64::INFINITY.to_bits()),
        CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0001),
        CandidateAttributeValue::floating_point_bits(0x7ff8_0000_0000_0002),
        CandidateAttributeValue::string(String::new()),
        CandidateAttributeValue::string("a".to_owned()),
        CandidateAttributeValue::string("aa".to_owned()),
        CandidateAttributeValue::string("b".to_owned()),
        CandidateAttributeValue::bytes(vec![]),
        CandidateAttributeValue::bytes(vec![0]),
        CandidateAttributeValue::bytes(vec![0, 0]),
        CandidateAttributeValue::bytes(vec![1]),
        CandidateAttributeValue::array(vec![]),
        CandidateAttributeValue::array(vec![CandidateAttributeValue::null()]),
        CandidateAttributeValue::array(vec![CandidateAttributeValue::boolean(false)]),
        CandidateAttributeValue::array(vec![
            CandidateAttributeValue::boolean(false),
            CandidateAttributeValue::null(),
        ]),
        CandidateAttributeValue::key_value_list(vec![]),
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "a".to_owned(),
            CandidateAttributeValue::null(),
        )]),
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "a".to_owned(),
            CandidateAttributeValue::boolean(false),
        )]),
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "b".to_owned(),
            CandidateAttributeValue::null(),
        )]),
    ]
    .into_iter()
    .map(|candidate| {
        candidate
            .validate_log_body(profile)
            .expect("comparison fixture is bounded")
    })
    .collect::<Vec<_>>();

    for left in &values {
        for right in &values {
            let mut left_key = Vec::new();
            left.append_comparison_encoding(&mut left_key)
                .expect("comparison encoding is bounded");
            let mut right_key = Vec::new();
            right
                .append_comparison_encoding(&mut right_key)
                .expect("comparison encoding is bounded");
            assert_eq!(
                left.cmp(right),
                left_key.cmp(&right_key),
                "comparison encoding diverged for {left:?} and {right:?}"
            );
            assert_eq!(
                left_key.len(),
                left.comparison_encoded_size_bytes()
                    .expect("comparison size is bounded")
            );
        }
    }
}

#[derive(Default)]
struct CountingObserver {
    structures: usize,
    payload_chunks: usize,
    fail_at_structure: Option<usize>,
}

impl NativeValueObserver for CountingObserver {
    type Error = &'static str;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        self.structures += 1;
        if self.fail_at_structure == Some(self.structures) {
            return Err("cancelled traversal");
        }
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        self.payload_chunks += 1;
        Ok(())
    }
}

#[test]
fn observed_native_traversal_preserves_every_kind_and_bounds_payload_polls() {
    let profile = ValueLimitProfile::release_1_system_maximum();
    let value = CandidateAttributeValue::array(vec![
        CandidateAttributeValue::null(),
        CandidateAttributeValue::boolean(true),
        CandidateAttributeValue::signed_integer(-7),
        CandidateAttributeValue::floating_point_bits((-0.0_f64).to_bits()),
        CandidateAttributeValue::string("s".repeat(1_025)),
        CandidateAttributeValue::bytes(vec![0xa5; 1_025]),
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "nested".to_owned(),
            CandidateAttributeValue::boolean(false),
        )]),
    ])
    .validate_log_body(profile)
    .expect("the mixed native fixture is within the release-one body bound");

    let mut equality = CountingObserver::default();
    assert!(
        value
            .equals_observed(&value, &mut equality)
            .expect("observation succeeds")
    );
    assert!(equality.structures >= 16);
    assert_eq!(equality.payload_chunks, 10);

    let mut sizing = CountingObserver::default();
    assert_eq!(
        value
            .retained_heap_bytes_observed(&mut sizing)
            .expect("observed sizing succeeds"),
        value
            .retained_heap_bytes()
            .expect("the bounded value has a retained size")
    );
    assert_eq!(sizing.payload_chunks, 5);

    let mut cloning = CountingObserver::default();
    assert_eq!(
        value
            .try_clone_observed(&mut cloning)
            .expect("observed clone succeeds"),
        value
    );
    assert_eq!(cloning.payload_chunks, 5);
}

#[test]
fn observed_native_equality_is_exact_and_propagates_cancellation() {
    let profile = ValueLimitProfile::release_1_system_maximum();
    let validated = |candidate: CandidateAttributeValue| {
        candidate
            .validate_log_body(profile)
            .expect("comparison fixture is bounded")
    };
    let cases = [
        validated(CandidateAttributeValue::null()),
        validated(CandidateAttributeValue::boolean(false)),
        validated(CandidateAttributeValue::signed_integer(1)),
        validated(CandidateAttributeValue::floating_point_bits(
            1.0_f64.to_bits(),
        )),
        validated(CandidateAttributeValue::string("value".to_owned())),
        validated(CandidateAttributeValue::bytes(vec![1, 2])),
        validated(CandidateAttributeValue::array(vec![
            CandidateAttributeValue::boolean(true),
        ])),
        validated(CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new("key".to_owned(), CandidateAttributeValue::null()),
        ])),
    ];
    for (index, left) in cases.iter().enumerate() {
        for (other_index, right) in cases.iter().enumerate() {
            let mut observer = CountingObserver::default();
            assert_eq!(
                left.equals_observed(right, &mut observer)
                    .expect("comparison observation succeeds"),
                index == other_index
            );
        }
    }

    let unequal_array = validated(CandidateAttributeValue::array(vec![]));
    let unequal_key_values = validated(CandidateAttributeValue::key_value_list(vec![]));
    let mut observer = CountingObserver::default();
    assert!(
        !cases[6]
            .equals_observed(&unequal_array, &mut observer)
            .expect("array length mismatch is explicit")
    );
    assert!(
        !cases[7]
            .equals_observed(&unequal_key_values, &mut observer)
            .expect("key/value length mismatch is explicit")
    );

    let mut cancelled = CountingObserver {
        fail_at_structure: Some(2),
        ..CountingObserver::default()
    };
    assert_eq!(
        cases[6].try_clone_observed(&mut cancelled),
        Err(ObservedValueFailure::Observer("cancelled traversal"))
    );
}

#[test]
fn projected_occurrence_accounting_and_encoding_cover_the_complete_bounded_set() {
    let profile = profile();
    let occurrences = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Resource,
        "service.name".to_owned(),
        vec![
            CandidateAttributeValue::string("api".to_owned()),
            CandidateAttributeValue::boolean(true),
        ],
    )
    .validate(profile)
    .expect("the projected occurrence fixture is bounded");
    let first = occurrences
        .occurrence(0)
        .expect("the first occurrence exists");
    assert!(AttributeOccurrenceSet::retained_occurrence_bytes(first).expect("size is bounded") > 3);
    assert_eq!(
        AttributeOccurrenceSet::projected_occurrence_capacity_bytes(profile)
            .expect("profile capacity is bounded"),
        usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .attributes_per_namespace()
                .value()
        )
        .expect("test profile count fits usize")
            * AttributeOccurrenceSet::PROJECTED_OCCURRENCE_SLOT_BYTES
    );
    assert!(
        occurrences
            .canonical_encoded_size_bytes()
            .expect("logical encoding is bounded")
            > occurrences.key().len()
    );
    let mut comparison = Vec::new();
    occurrences
        .visit_comparison_encoding(&mut |bytes| {
            comparison.extend_from_slice(bytes);
            Ok::<(), core::convert::Infallible>(())
        })
        .expect("comparison visitor is infallible");
    assert!(!comparison.is_empty());
    assert_eq!(
        occurrences.try_clone().expect("bounded clone succeeds"),
        occurrences
    );

    assert!(
        AttributeOccurrenceSet::from_validated(
            AttributeNamespace::Record,
            String::new(),
            vec![first.try_clone().expect("bounded value clone succeeds")],
            profile,
        )
        .is_err(),
        "an empty projected key remains invalid"
    );
}
