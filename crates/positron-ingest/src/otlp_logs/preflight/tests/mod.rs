use super::validate_record_count as validate_with_profile;
use crate::ReceiveFailure;
use positron_domain::value::ValueLimitProfile;

mod json;

const CONTAINER_LIMIT: usize = 1_024;
const ATTRIBUTE_LIMIT: usize = 1_024;
const COLLECTION_LIMIT: usize = 1_024;

#[test]
fn every_repeated_container_has_an_inclusive_pre_decode_limit() {
    for build in [
        request_with_empty_resources as fn(usize) -> Vec<u8>,
        request_with_empty_scopes,
        request_with_empty_records,
    ] {
        assert_eq!(validate_record_count(&build(CONTAINER_LIMIT)), Ok(()));
        assert_eq!(
            validate_record_count(&build(CONTAINER_LIMIT + 1)),
            Err(ReceiveFailure::ValueLimitExceeded),
        );
    }
    assert_eq!(
        validate_record_count(&request_with_empty_attributes(ATTRIBUTE_LIMIT)),
        Ok(())
    );
    assert_eq!(
        validate_record_count(&request_with_empty_attributes(ATTRIBUTE_LIMIT + 1)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
    assert_eq!(
        validate_record_count(&request_with_aggregate_attributes(4_096)),
        Ok(())
    );
    assert_eq!(
        validate_record_count(&request_with_aggregate_attributes(4_097)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
    for build in [
        request_with_empty_kvlist_entries as fn(usize) -> Vec<u8>,
        request_with_empty_array_values,
    ] {
        assert_eq!(validate_record_count(&build(COLLECTION_LIMIT)), Ok(()));
        assert_eq!(
            validate_record_count(&build(COLLECTION_LIMIT + 1)),
            Err(ReceiveFailure::ValueLimitExceeded),
        );
    }
}

#[test]
fn adversarial_empty_container_fanout_is_rejected_without_decoding() {
    for build in [
        request_with_empty_resources as fn(usize) -> Vec<u8>,
        request_with_empty_scopes,
        request_with_empty_records,
        request_with_empty_attributes,
        request_with_empty_kvlist_entries,
        request_with_empty_array_values,
    ] {
        let request = build(100_000);
        assert!(request.len() < 1_048_576);
        assert_eq!(
            validate_record_count(&request),
            Err(ReceiveFailure::ValueLimitExceeded),
        );
    }
}

#[test]
fn nested_dynamic_collections_stop_before_decode_allocation() {
    assert_eq!(
        validate_record_count(&request_with_nested_array(128)),
        Ok(())
    );
    assert_eq!(
        validate_record_count(&request_with_nested_array(129)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
}

fn validate_record_count(protobuf: &[u8]) -> Result<(), ReceiveFailure> {
    validate_with_profile(protobuf, ValueLimitProfile::release_1_system_maximum())
}

#[test]
fn every_nested_allocation_path_and_varint_overflow_is_covered() {
    let nested_value = message(5, &message(1, &[]));
    let key_value = message(2, &nested_value);
    let resource = message(1, &key_value);
    let scope = message(3, &key_value);
    let record = message(6, &key_value);
    let mut scope_logs = message(1, &scope);
    scope_logs.extend_from_slice(&message(2, &record));
    let mut resource_logs = message(1, &resource);
    resource_logs.extend_from_slice(&message(2, &scope_logs));
    resource_logs.extend_from_slice(&message(9, &[]));
    assert_eq!(validate_record_count(&message(1, &resource_logs)), Ok(()));

    let overflow = [
        0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
    ];
    assert_eq!(
        validate_record_count(&overflow),
        Err(ReceiveFailure::MalformedPayload),
    );
}

#[test]
fn unrelated_length_delimited_fields_do_not_count_as_known_containers() {
    let log_like_bytes = request_with_empty_records(CONTAINER_LIMIT + 1);
    let mut request = Vec::new();
    push_length_delimited(9, &log_like_bytes, &mut request);
    push_length_delimited(1, &[0x0a, 0x02, 0x12, 0x00], &mut request);

    assert_eq!(validate_record_count(&request), Ok(()));
}

#[test]
fn malformed_nested_wire_is_rejected() {
    for request in [
        vec![0x0a, 0x02, 0x12],
        vec![0x0a, 0x03, 0x12, 0x01, 0x80],
        vec![
            0x0a, 0x0b, 0x12, 0x09, 0x12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        ],
    ] {
        assert_eq!(
            validate_record_count(&request),
            Err(ReceiveFailure::MalformedPayload),
        );
    }
}

#[test]
fn unknown_wire_types_are_skipped_and_group_hazards_fail_closed() {
    let valid_unknowns = [
        0x10, 0x01, 0x19, 0, 0, 0, 0, 0, 0, 0, 0, 0x25, 0, 0, 0, 0, 0x2b, 0x30, 0x01, 0x2c,
    ];
    assert_eq!(validate_record_count(&valid_unknowns), Ok(()));

    for malformed in [
        vec![0x00],
        vec![0x0e],
        vec![0x0c],
        vec![0x0a, 0x80, 0x00],
        vec![0x11, 0, 0, 0],
        vec![0x1d, 0, 0],
        vec![0x0b, 0x14],
    ] {
        assert_eq!(
            validate_record_count(&malformed),
            Err(ReceiveFailure::MalformedPayload),
        );
    }

    let mut too_deep = Vec::new();
    too_deep.extend(std::iter::repeat_n(0x0b, 65));
    too_deep.extend(std::iter::repeat_n(0x0c, 65));
    assert_eq!(
        validate_record_count(&too_deep),
        Err(ReceiveFailure::MalformedPayload),
    );
}

fn request_with_empty_resources(count: usize) -> Vec<u8> {
    repeated_messages(1, &[], count)
}

fn request_with_empty_scopes(count: usize) -> Vec<u8> {
    let resource_logs = repeated_messages(2, &[], count);
    message(1, &resource_logs)
}

fn request_with_empty_records(count: usize) -> Vec<u8> {
    let scope_logs = repeated_messages(2, &[], count);
    request_with_scope_logs(&scope_logs)
}

fn request_with_empty_attributes(count: usize) -> Vec<u8> {
    let resource = repeated_messages(1, &[], count);
    let resource_logs = message(1, &resource);
    message(1, &resource_logs)
}

fn request_with_aggregate_attributes(count: usize) -> Vec<u8> {
    let mut request = Vec::new();
    for chunk in (0..count).collect::<Vec<_>>().chunks(ATTRIBUTE_LIMIT) {
        let resource = repeated_messages(1, &[], chunk.len());
        request.extend_from_slice(&message(1, &message(1, &resource)));
    }
    request
}

fn request_with_empty_kvlist_entries(count: usize) -> Vec<u8> {
    let list = repeated_messages(1, &[], count);
    request_with_body(&message(6, &list))
}

fn request_with_empty_array_values(count: usize) -> Vec<u8> {
    let array = repeated_messages(1, &[], count);
    request_with_body(&message(5, &array))
}

fn request_with_nested_array(depth: usize) -> Vec<u8> {
    let mut value = Vec::new();
    for _ in 0..depth {
        value = message(5, &message(1, &value));
    }
    request_with_body(&value)
}

fn request_with_body(any_value: &[u8]) -> Vec<u8> {
    let record = message(5, any_value);
    let scope_logs = message(2, &record);
    request_with_scope_logs(&scope_logs)
}

fn request_with_scope_logs(scope_logs: &[u8]) -> Vec<u8> {
    let resource_logs = message(2, scope_logs);
    message(1, &resource_logs)
}

fn repeated_messages(field: u64, value: &[u8], count: usize) -> Vec<u8> {
    let mut output = Vec::new();
    for _ in 0..count {
        push_length_delimited(field, value, &mut output);
    }
    output
}

fn message(field: u64, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    push_length_delimited(field, value, &mut output);
    output
}

fn push_length_delimited(field: u64, value: &[u8], output: &mut Vec<u8>) {
    push_varint((field << 3) | 2, output);
    push_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn push_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}
