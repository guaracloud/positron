use super::{TraceReceiveFailure, preflight_otlp_traces_json};

#[test]
fn protojson_scalar_forms_are_bounded_before_generated_decode() {
    for payload in [
        br#"true"#.as_slice(),
        br#"17"#.as_slice(),
        br#"-17"#.as_slice(),
        br#"1.25"#.as_slice(),
        br#"null"#.as_slice(),
        br#""escaped\ntext""#.as_slice(),
    ] {
        assert_eq!(preflight_otlp_traces_json(payload), Ok(()), "{payload:?}");
    }
}

#[test]
fn protojson_scalar_syntax_failures_keep_the_malformed_public_class() {
    for payload in [b"01".as_slice(), b"1.".as_slice(), b"tru".as_slice()] {
        assert_eq!(
            preflight_otlp_traces_json(payload),
            Err(TraceReceiveFailure::MalformedPayload),
            "invalid ProtoJSON scalar: {payload:?}"
        );
    }
}
