use super::{TraceReceiveFailure, preflight_otlp_traces_protobuf};

#[test]
fn nested_unknown_fields_and_fixed_width_values_remain_ignorable() {
    let any_value = message(&[(99, 2, &[0xaa, 0xbb]), (100, 1, &[0; 8]), (101, 5, &[0; 4])]);
    let key_value = message(&[(2, 2, &any_value)]);
    let resource = message(&[(1, 2, &key_value), (99, 2, &[0xcc])]);
    let scope = message(&[(3, 2, &key_value), (100, 1, &[0; 8])]);
    let span = message(&[(9, 2, &key_value)]);
    let scope_spans = message(&[(1, 2, &scope), (2, 2, &span), (101, 5, &[0; 4])]);
    let resource_spans = message(&[(1, 2, &resource), (2, 2, &scope_spans), (102, 2, &[0xdd])]);
    let request = message(&[(1, 2, &resource_spans)]);

    assert_eq!(preflight_otlp_traces_protobuf(&request), Ok(()));
}

#[test]
fn malformed_varints_and_group_boundaries_are_stable_failures() {
    let malformed = [
        vec![0x80, 0x00],
        vec![0x80; 10],
        [vec![0x80; 9], vec![0x02]].concat(),
        vec![0x3c],
        group(7, 8),
        deeply_nested_groups(65),
    ];

    for payload in malformed {
        assert_eq!(
            preflight_otlp_traces_protobuf(&payload),
            Err(TraceReceiveFailure::MalformedPayload),
            "malformed protobuf shape must fail closed: {payload:?}"
        );
    }

    assert_eq!(
        preflight_otlp_traces_protobuf(&deeply_nested_groups(64)),
        Ok(())
    );
}

fn message(fields: &[(u64, u8, &[u8])]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for &(field, wire, value) in fields {
        put_varint((field << 3) | u64::from(wire), &mut encoded);
        match wire {
            0 | 1 | 5 => encoded.extend_from_slice(value),
            2 => {
                put_varint(value.len() as u64, &mut encoded);
                encoded.extend_from_slice(value);
            },
            _ => unreachable!("test fixtures only use supported non-group wires"),
        }
    }
    encoded
}

fn group(start: u64, end: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    put_varint((start << 3) | 3, &mut encoded);
    put_varint((end << 3) | 4, &mut encoded);
    encoded
}

fn deeply_nested_groups(count: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    for field in 100..(100 + count) {
        put_varint((field as u64) << 3 | 3, &mut encoded);
    }
    for field in (100..(100 + count)).rev() {
        put_varint((field as u64) << 3 | 4, &mut encoded);
    }
    encoded
}

fn put_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}
