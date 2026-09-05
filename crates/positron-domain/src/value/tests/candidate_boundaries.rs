use super::*;

use crate::outcome::DomainFailureCode;
use crate::value::{CandidateShapeFailure, ValueLimitDimension};

#[test]
fn detailed_shape_reports_the_canonical_dynamic_limit_dimension() {
    let cases = [
        (
            CandidateAttributeValue::string("12345".to_owned()),
            profile_with_dynamic(4, 8, 64, 4, 8, 8),
            ValueLimitDimension::IndividualValueBytes,
            5,
            4,
        ),
        (
            CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                "12345".to_owned(),
                CandidateAttributeValue::null(),
            )]),
            profile_with_dynamic(64, 8, 4, 4, 8, 8),
            ValueLimitDimension::KeyPathBytes,
            5,
            4,
        ),
        (
            CandidateAttributeValue::array(vec![CandidateAttributeValue::array(vec![
                CandidateAttributeValue::null(),
            ])]),
            profile_with_dynamic(64, 8, 64, 1, 8, 8),
            ValueLimitDimension::NestingDepth,
            1,
            0,
        ),
        (
            CandidateAttributeValue::array(vec![
                CandidateAttributeValue::null(),
                CandidateAttributeValue::null(),
            ]),
            profile_with_dynamic(64, 8, 64, 4, 1, 8),
            ValueLimitDimension::ArrayEntries,
            2,
            1,
        ),
        (
            CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new("one".to_owned(), CandidateAttributeValue::null()),
                CandidateKeyValue::new("two".to_owned(), CandidateAttributeValue::null()),
            ]),
            profile_with_dynamic(64, 8, 64, 4, 8, 1),
            ValueLimitDimension::KeyValueListEntries,
            2,
            1,
        ),
        (
            CandidateAttributeValue::array(vec![
                CandidateAttributeValue::string("123".to_owned()),
                CandidateAttributeValue::string("456".to_owned()),
            ]),
            profile_with_dynamic(4, 8, 64, 4, 8, 8),
            ValueLimitDimension::IndividualValueBytes,
            6,
            4,
        ),
    ];

    for (candidate, profile, dimension, actual, allowed) in cases {
        let failure = candidate
            .validate_shape_detailed(profile)
            .expect_err("candidate exceeds the selected dynamic limit");
        let CandidateShapeFailure::Limit(violation) = failure else {
            panic!("shape failure should carry a semantic limit");
        };
        assert_eq!(violation.dimension(), dimension);
        assert_eq!(violation.actual(), actual);
        assert_eq!(violation.allowed(), allowed);
        let legacy = candidate
            .validate_shape(profile)
            .expect_err("legacy validation remains a generic value-limit failure");
        assert_eq!(legacy.code(), DomainFailureCode::ValueLimitExceeded);
    }

    let nested = CandidateAttributeValue::key_value_list(vec![
        CandidateKeyValue::new(
            "long-entry-key".to_owned(),
            CandidateAttributeValue::string("12".to_owned()),
        ),
        CandidateKeyValue::new(
            "another-entry-key".to_owned(),
            CandidateAttributeValue::string("34".to_owned()),
        ),
    ]);
    let profile = profile_with_dynamic(4, 8, 64, 4, 8, 8);
    assert!(nested.validate_shape_detailed(profile).is_ok());
    assert!(nested.validate_attribute(profile).is_ok());
}

fn profile_with_dynamic(
    individual: u32,
    attributes: u32,
    key_path: u32,
    depth: u16,
    array_entries: u32,
    key_value_entries: u32,
) -> ValueLimitProfile {
    let bytes = ByteLimit::new(64).expect("fixture byte limit is nonzero");
    let request = RequestLimits::new(
        bytes,
        bytes,
        CollectionLimit::new(8).expect("fixture collection limit is nonzero"),
        CollectionLimit::new(8).expect("fixture collection limit is nonzero"),
    );
    let record = RecordLimits::new(bytes, bytes, bytes);
    let dynamic = DynamicValueLimits::new(
        ByteLimit::new(individual).expect("fixture value limit is nonzero"),
        CollectionLimit::new(attributes).expect("fixture collection limit is nonzero"),
        ByteLimit::new(key_path).expect("fixture key limit is nonzero"),
        NestingLimit::new(depth).expect("fixture depth limit is valid"),
        CollectionLimit::new(array_entries).expect("fixture collection limit is nonzero"),
        CollectionLimit::new(key_value_entries).expect("fixture collection limit is nonzero"),
    );
    ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
        .validate()
        .expect("fixture tenant limits do not raise system ceilings")
}

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
