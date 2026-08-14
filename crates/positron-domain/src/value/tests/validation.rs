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
