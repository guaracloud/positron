use super::*;

use crate::outcome::DomainFailureCode;

#[test]
fn validate_shape_accepts_lowered_collection_and_scalar_boundaries() {
    let profile = profile_with_value_and_body_bytes(64, 64);
    let dynamic = profile.effective_limits().dynamic_value();
    let collection_limit = usize::try_from(dynamic.array_entries().value()).expect("small limit");

    let array_at_limit = CandidateAttributeValue::array(
        (0..collection_limit)
            .map(|_| CandidateAttributeValue::boolean(true))
            .collect(),
    );
    assert!(array_at_limit.validate_shape(profile).is_ok());
    assert_value_limit_exceeded(
        CandidateAttributeValue::array(
            (0..=collection_limit)
                .map(|_| CandidateAttributeValue::boolean(true))
                .collect(),
        ),
        profile,
    );

    let list_at_limit = CandidateAttributeValue::key_value_list(
        (0..collection_limit)
            .map(|_| CandidateKeyValue::new("entry".to_owned(), CandidateAttributeValue::null()))
            .collect(),
    );
    assert!(list_at_limit.validate_shape(profile).is_ok());
    assert_value_limit_exceeded(
        CandidateAttributeValue::key_value_list(
            (0..=collection_limit)
                .map(|_| {
                    CandidateKeyValue::new("entry".to_owned(), CandidateAttributeValue::null())
                })
                .collect(),
        ),
        profile,
    );

    let key_limit = usize::try_from(dynamic.key_path_bytes().value()).expect("small limit");
    assert!(
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "k".repeat(key_limit),
            CandidateAttributeValue::null(),
        )])
        .validate_shape(profile)
        .is_ok()
    );
    assert_value_limit_exceeded(
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            "k".repeat(key_limit + 1),
            CandidateAttributeValue::null(),
        )]),
        profile,
    );
    assert_value_limit_exceeded(
        CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
            String::new(),
            CandidateAttributeValue::null(),
        )]),
        profile,
    );

    let value_limit =
        usize::try_from(dynamic.individual_value_bytes().value()).expect("small limit");
    assert!(
        CandidateAttributeValue::string("s".repeat(value_limit))
            .validate_shape(profile)
            .is_ok()
    );
    assert_value_limit_exceeded(
        CandidateAttributeValue::string("s".repeat(value_limit + 1)),
        profile,
    );
    assert!(
        CandidateAttributeValue::bytes(vec![0xa5; value_limit])
            .validate_shape(profile)
            .is_ok()
    );
    assert_value_limit_exceeded(
        CandidateAttributeValue::bytes(vec![0xa5; value_limit + 1]),
        profile,
    );
}

fn assert_value_limit_exceeded(candidate: CandidateAttributeValue, profile: ValueLimitProfile) {
    let failure = candidate
        .validate_shape(profile)
        .expect_err("candidate must exceed the lowered profile boundary");
    assert_eq!(failure.code(), DomainFailureCode::ValueLimitExceeded);
}
