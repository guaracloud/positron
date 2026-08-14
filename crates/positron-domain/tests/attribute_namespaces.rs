use positron_domain::value::AttributeNamespace;

#[test]
fn stream_attributes_have_a_distinct_stable_namespace() {
    assert_eq!(AttributeNamespace::Stream.as_str(), "stream");
}
