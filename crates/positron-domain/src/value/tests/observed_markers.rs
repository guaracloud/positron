use super::*;
use crate::value::{AttributeValueKind, MarkerAction};

#[derive(Default)]
struct NoopObserver;

impl NativeValueObserver for NoopObserver {
    type Error = ();

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn observed_marker_encoding_covers_all_actions_and_original_kinds() {
    let profile = super::profile();
    let kinds = [
        (AttributeValueKind::Null, 0),
        (AttributeValueKind::Boolean, 1),
        (AttributeValueKind::SignedInteger, 2),
        (AttributeValueKind::FloatingPoint, 3),
        (AttributeValueKind::String, 4),
        (AttributeValueKind::Bytes, 5),
        (AttributeValueKind::Array, 6),
        (AttributeValueKind::KeyValueList, 7),
    ];

    for (kind, kind_tag) in kinds {
        let candidate = CandidateAttributeValue::redaction_marker(kind, MarkerAction::Redacted);
        let mut observer = NoopObserver;
        let transfer = candidate
            .validate_attribute_observed_with_facts(profile, &mut observer)
            .expect("a payload-free marker validates");
        assert_eq!(transfer.value().kind(), AttributeValueKind::Marker);
        assert_eq!(transfer.value_size_bytes(), 0);
        assert_eq!(transfer.retained_heap_bytes(), 0);
        assert_eq!(
            transfer
                .value()
                .canonical_encoded_size_bytes_observed(&mut observer)
                .expect("marker canonical size is observed"),
            3
        );
        let mut encoded = Vec::new();
        transfer
            .value()
            .visit_canonical_encoding_observed(&mut observer, &mut |bytes| {
                encoded.extend_from_slice(bytes)
            })
            .expect("marker encoding is observed");
        assert_eq!(encoded, vec![8, 1, kind_tag]);
    }

    let removed =
        CandidateAttributeValue::redaction_marker(AttributeValueKind::Null, MarkerAction::Removed)
            .validate_attribute(profile)
            .expect("removed marker validates");
    let mut observer = NoopObserver;
    let mut encoded = Vec::new();
    removed
        .visit_canonical_encoding_observed(&mut observer, &mut |bytes| {
            encoded.extend_from_slice(bytes)
        })
        .expect("removed marker encoding is observed");
    assert_eq!(encoded, vec![8, 0, 0]);

    let truncated_bytes = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("x".to_owned()),
        MarkerAction::TruncatedBytes,
    )
    .validate_attribute(profile)
    .expect("byte truncation validates");
    encoded.clear();
    assert_eq!(
        truncated_bytes
            .canonical_encoded_size_bytes_observed(&mut observer)
            .expect("byte truncation canonical size is observed"),
        13
    );
    truncated_bytes
        .visit_canonical_encoding_observed(&mut observer, &mut |bytes| {
            encoded.extend_from_slice(bytes)
        })
        .expect("byte truncation encoding is observed");
    assert_eq!(encoded, vec![8, 2, 4, 4, 0, 0, 0, 0, 0, 0, 0, 1, b'x']);

    let nested = CandidateAttributeValue::truncated(
        CandidateAttributeValue::array(vec![
            CandidateAttributeValue::redaction_marker(
                AttributeValueKind::String,
                MarkerAction::Removed,
            ),
            CandidateAttributeValue::string("x".to_owned()),
        ]),
        MarkerAction::TruncatedElements,
    )
    .validate_attribute(profile)
    .expect("collection truncation retains nested marker leaves");
    assert!(nested.contains_marker());
    assert_eq!(nested.array_len(), Some(2));
    encoded.clear();
    assert_eq!(
        nested
            .canonical_encoded_size_bytes_observed(&mut observer)
            .expect("collection truncation canonical size is observed"),
        25
    );
    nested
        .visit_canonical_encoding_observed(&mut observer, &mut |bytes| {
            encoded.extend_from_slice(bytes)
        })
        .expect("collection truncation encoding is observed");
    assert_eq!(
        encoded,
        vec![
            8, 3, 6, 6, 0, 0, 0, 0, 0, 0, 0, 2, 8, 0, 4, 4, 0, 0, 0, 0, 0, 0, 0, 1, b'x'
        ]
    );
}

#[test]
fn observed_native_comparison_sizing_and_clone_cover_sanitized_value_shapes() {
    let profile = super::profile();
    let string = CandidateAttributeValue::string("left".to_owned())
        .validate_attribute(profile)
        .expect("string validates");
    let same_string = CandidateAttributeValue::string("left".to_owned())
        .validate_attribute(profile)
        .expect("string validates");
    let other_string = CandidateAttributeValue::string("right".to_owned())
        .validate_attribute(profile)
        .expect("string validates");
    let bytes = CandidateAttributeValue::bytes(vec![1, 2])
        .validate_attribute(profile)
        .expect("bytes validate");
    let other_bytes = CandidateAttributeValue::bytes(vec![1, 3])
        .validate_attribute(profile)
        .expect("bytes validate");
    let array =
        CandidateAttributeValue::array(vec![CandidateAttributeValue::string("item".to_owned())])
            .validate_attribute(profile)
            .expect("array validates");
    let empty_array = CandidateAttributeValue::array(Vec::new())
        .validate_attribute(profile)
        .expect("empty array validates");
    let entries = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "key".to_owned(),
        CandidateAttributeValue::string("value".to_owned()),
    )])
    .validate_attribute(profile)
    .expect("key/value list validates");
    let other_entries = CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
        "other".to_owned(),
        CandidateAttributeValue::string("value".to_owned()),
    )])
    .validate_attribute(profile)
    .expect("key/value list validates");
    let truncated = CandidateAttributeValue::truncated(
        CandidateAttributeValue::string("left".to_owned()),
        MarkerAction::TruncatedBytes,
    )
    .validate_attribute(profile)
    .expect("sanitized truncation validates");

    let mut observer = NoopObserver;
    assert!(
        string
            .equals_observed(&same_string, &mut observer)
            .expect("equal strings compare")
    );
    assert!(
        !string
            .equals_observed(&other_string, &mut observer)
            .expect("different strings compare")
    );
    assert!(
        !bytes
            .equals_observed(&other_bytes, &mut observer)
            .expect("different bytes compare")
    );
    assert!(
        !array
            .equals_observed(&empty_array, &mut observer)
            .expect("different arrays compare")
    );
    assert!(
        !entries
            .equals_observed(&other_entries, &mut observer)
            .expect("different keys compare")
    );
    assert!(
        truncated
            .equals_observed(&truncated, &mut observer)
            .expect("truncated values compare through their children")
    );
    assert!(
        truncated
            .equals_observed(&string, &mut observer)
            .expect("truncated value compares with its sanitized native value")
    );
    assert!(
        string
            .equals_observed(&truncated, &mut observer)
            .expect("native value compares with a sanitized truncation")
    );

    assert_eq!(string.retained_heap_bytes_observed(&mut observer), Ok(4));
    assert_eq!(bytes.retained_heap_bytes_observed(&mut observer), Ok(2));
    assert_eq!(array.retained_heap_bytes_observed(&mut observer), Ok(68));
    assert_eq!(entries.retained_heap_bytes_observed(&mut observer), Ok(104));

    assert_eq!(
        string
            .try_clone_observed(&mut observer)
            .expect("string clones"),
        string
    );
    assert_eq!(
        bytes
            .try_clone_observed(&mut observer)
            .expect("bytes clone"),
        bytes
    );
    assert_eq!(
        array
            .try_clone_observed(&mut observer)
            .expect("array clones"),
        array
    );
    assert_eq!(
        entries
            .try_clone_observed(&mut observer)
            .expect("key/value list clones"),
        entries
    );
}
