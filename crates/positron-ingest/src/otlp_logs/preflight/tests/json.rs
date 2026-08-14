use super::super::validate_json;
use crate::ReceiveFailure;
use positron_domain::value::ValueLimitProfile;

#[test]
fn every_json_repeated_container_has_an_inclusive_pre_decode_limit() {
    assert_eq!(validate(&request_with_resources(1_024)), Ok(()));
    assert_eq!(
        validate(&request_with_resources(1_025)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
    assert_eq!(validate(&request_with_records(1_024)), Ok(()));
    assert_eq!(
        validate(&request_with_records(1_025)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
}

#[test]
fn json_attributes_and_nested_any_values_are_bounded_before_serde() {
    assert_eq!(validate(&request_with_attributes(1_024)), Ok(()));
    assert_eq!(
        validate(&request_with_attributes(1_025)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
    assert_eq!(validate(&request_with_aggregate_attributes(4_096)), Ok(()));
    assert_eq!(
        validate(&request_with_aggregate_attributes(4_097)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
    assert_eq!(validate(&request_with_nested_arrays(128)), Ok(()));
    assert_eq!(
        validate(&request_with_nested_arrays(129)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
}

#[test]
fn decoded_string_and_base64_sizes_have_exact_inclusive_bounds() {
    assert_eq!(
        validate(&request_with_body("stringValue", &"a".repeat(65_536))),
        Ok(())
    );
    assert_eq!(
        validate(&request_with_body("stringValue", &"a".repeat(65_537))),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
    assert_eq!(
        validate(&request_with_body("stringValue", &"é".repeat(32_768))),
        Ok(()),
    );
    assert_eq!(
        validate(&request_with_body("stringValue", &"é".repeat(32_769))),
        Err(ReceiveFailure::ValueLimitExceeded),
    );

    let at_limit = format!("{}\\u0041==", "A".repeat(87_381));
    let over_limit = format!("{}\\u0041=", "A".repeat(87_382));
    assert_eq!(
        validate(&request_with_body("bytesValue", &at_limit)),
        Ok(())
    );
    assert_eq!(
        validate(&request_with_body("bytesValue", &over_limit)),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
}

#[test]
fn malformed_json_and_escaped_structural_names_fail_closed() {
    for malformed in [
        br#"{"resourceLogs":[{},]}"#.as_slice(),
        br#"{"resourceLogs":"wrong"}"#,
        br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"\uD800"}}]}]}]}"#,
        br#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"bytesValue":"%%%="}}]}]}]}"#,
    ] {
        assert_eq!(validate(malformed), Err(ReceiveFailure::MalformedPayload));
    }

    let escaped_name = format!(
        "{{\"resource\\u004cogs\":[{}]}}",
        vec!["{}"; 1_025].join(",")
    );
    assert_eq!(
        validate(escaped_name.as_bytes()),
        Err(ReceiveFailure::ValueLimitExceeded),
    );
}

#[test]
fn json_scalar_escape_and_number_grammar_is_streamed_without_materialization() {
    let valid = br#"{
        "\"": null,
        "\\": true,
        "\/": false,
        "\b": -0,
        "\f": 12,
        "\n": 1.25,
        "\r": 2e+3,
        "\t": "raw \u00e9",
        "\u0100": "\uD83D\uDE00",
        "nested": {"values": [null, true, false, -12.5e-2]}
    }"#;
    assert_eq!(validate(valid), Ok(()));

    for malformed in [
        br#"{} trailing"#.as_slice(),
        br#"{"x":"unterminated}"#,
        br#"{"x":"\"}"#,
        br#"{"x":"\q"}"#,
        br#"{"x":"\u12"}"#,
        br#"{"x":"\uD800x"}"#,
        br#"{"x":"\uD800\u0041"}"#,
        br#"{"x":"\uDC00"}"#,
        br#"{"x":tru}"#,
        br#"{"x":-}"#,
        br#"{"x":01}"#,
        br#"{"x":1.}"#,
        br#"{"x":1e}"#,
        br#"{"x":1e+}"#,
        br#"{"x":@}"#,
    ] {
        assert_eq!(validate(malformed), Err(ReceiveFailure::MalformedPayload));
    }

    let invalid_utf8 = b"{\"x\":\"\xff\"}";
    assert_eq!(
        validate(invalid_utf8),
        Err(ReceiveFailure::MalformedPayload)
    );
}

#[test]
fn base64_padding_and_escaped_alphabet_are_validated_exactly() {
    for malformed in ["A===", "AAA", "AA=A", "\\u00e9AAA", "\\u0100AAA"] {
        assert_eq!(
            validate(&request_with_body("bytesValue", malformed)),
            Err(ReceiveFailure::MalformedPayload),
        );
    }
    for valid in ["", "AA==", "AAA=", "QUJD", "\\u0051UJD"] {
        assert_eq!(validate(&request_with_body("bytesValue", valid)), Ok(()));
    }
}

#[test]
fn json_dynamic_collection_fanout_is_bounded_per_collection() {
    for keyed in [false, true] {
        assert_eq!(validate(&request_with_dynamic_values(1_024, keyed)), Ok(()));
        assert_eq!(
            validate(&request_with_dynamic_values(1_025, keyed)),
            Err(ReceiveFailure::ValueLimitExceeded),
        );
    }
}

fn validate(json: &[u8]) -> Result<(), ReceiveFailure> {
    validate_json(json, ValueLimitProfile::release_1_system_maximum())
}

fn request_with_resources(count: usize) -> Vec<u8> {
    format!("{{\"resourceLogs\":[{}]}}", vec!["{}"; count].join(",")).into_bytes()
}

fn request_with_records(count: usize) -> Vec<u8> {
    format!(
        "{{\"resourceLogs\":[{{\"scopeLogs\":[{{\"logRecords\":[{}]}}]}}]}}",
        vec!["{}"; count].join(",")
    )
    .into_bytes()
}

fn request_with_attributes(count: usize) -> Vec<u8> {
    format!(
        "{{\"resourceLogs\":[{{\"resource\":{{\"attributes\":[{}]}}}}]}}",
        vec![r#"{"key":"k","value":{"boolValue":true}}"#; count].join(",")
    )
    .into_bytes()
}

fn request_with_aggregate_attributes(count: usize) -> Vec<u8> {
    let attributes = (0..count)
        .collect::<Vec<_>>()
        .chunks(1_024)
        .map(|chunk| {
            format!(
                r#"{{"resource":{{"attributes":[{}]}}}}"#,
                vec![r#"{"key":"k","value":{"boolValue":true}}"#; chunk.len()].join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"resourceLogs":[{attributes}]}}"#).into_bytes()
}

fn request_with_nested_arrays(depth: usize) -> Vec<u8> {
    let mut value = r#"{"boolValue":true}"#.to_owned();
    for _ in 0..depth {
        value = format!(r#"{{"arrayValue":{{"values":[{value}]}}}}"#);
    }
    format!(r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"body":{value}}}]}}]}}]}}"#)
        .into_bytes()
}

fn request_with_body(kind: &str, value: &str) -> Vec<u8> {
    format!(
        r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"body":{{"{kind}":"{value}"}}}}]}}]}}]}}"#
    )
    .into_bytes()
}

fn request_with_dynamic_values(count: usize, keyed: bool) -> Vec<u8> {
    let (kind, entry) = if keyed {
        ("kvlistValue", r#"{"key":"k","value":{"boolValue":true}}"#)
    } else {
        ("arrayValue", r#"{"boolValue":true}"#)
    };
    format!(
        r#"{{"resourceLogs":[{{"scopeLogs":[{{"logRecords":[{{"body":{{"{kind}":{{"values":[{}]}}}}}}]}}]}}]}}"#,
        vec![entry; count].join(",")
    )
    .into_bytes()
}
