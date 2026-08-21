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
