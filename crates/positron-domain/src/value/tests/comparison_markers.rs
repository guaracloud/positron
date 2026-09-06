use super::*;

use crate::value::{AttributeValueKind, MarkerAction};
use std::cmp::Ordering;

#[test]
fn truncated_string_uses_sanitized_value_for_order_preserving_comparison() {
    let profile = profile();
    let truncated = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("left".to_owned()),
        MarkerAction::TruncatedBytes,
    )
    .validate_attribute(profile)
    .expect("sanitized truncation validates");
    let sanitized = CandidateAttributeValue::string("left".to_owned())
        .validate_attribute(profile)
        .expect("sanitized string validates");
    let lower = CandidateAttributeValue::string("lead".to_owned())
        .validate_attribute(profile)
        .expect("lower neighbor validates");
    let upper = CandidateAttributeValue::string("lift".to_owned())
        .validate_attribute(profile)
        .expect("upper neighbor validates");

    assert_eq!(truncated.kind(), AttributeValueKind::String);
    assert_eq!(truncated.cmp(&sanitized), Ordering::Equal);
    assert_eq!(sanitized.cmp(&truncated), Ordering::Equal);
    assert_eq!(truncated.cmp(&lower), Ordering::Greater);
    assert_eq!(truncated.cmp(&upper), Ordering::Less);

    let expected = vec![4, 1, b'l', 1, b'e', 1, b'f', 1, b't', 0];
    let mut encoded = Vec::new();
    truncated
        .append_comparison_encoding(&mut encoded)
        .expect("comparison encoding is bounded");
    assert_eq!(encoded, expected);
    assert_eq!(
        truncated.comparison_encoded_size_bytes(),
        Ok(expected.len())
    );
    assert_eq!(
        sanitized.comparison_encoded_size_bytes(),
        Ok(expected.len())
    );
}
