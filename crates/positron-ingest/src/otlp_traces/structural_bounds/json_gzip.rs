use std::io::Write;

use super::super::{TraceReceiveFailure, preflight_otlp_traces_gzip, preflight_otlp_traces_json};
use super::support::MAX_BYTES;

#[test]
fn json_bounds_reject_overlong_strings_and_structural_depth_without_intermediate_trees() {
    let exact = format!(r#"{{"unknown":"{}"}}"#, "x".repeat(65_536));
    assert_eq!(preflight_otlp_traces_json(exact.as_bytes()), Ok(()));
    let over = format!(r#"{{"unknown":"{}"}}"#, "x".repeat(65_537));
    assert_eq!(
        preflight_otlp_traces_json(over.as_bytes()),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let exact_containers = format!(r#"{{"unknown":[{}]}}"#, vec!["[]"; 1_022].join(","));
    assert_eq!(
        preflight_otlp_traces_json(exact_containers.as_bytes()),
        Ok(())
    );
    let too_many_arrays = format!(r#"{{"unknown":[{}]}}"#, vec!["[]"; 1_023].join(","));
    assert_eq!(
        preflight_otlp_traces_json(too_many_arrays.as_bytes()),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );
    assert_eq!(
        preflight_otlp_traces_json(br#"{"unknown":[]} trailing"#),
        Err(TraceReceiveFailure::MalformedPayload)
    );

    let exact_depth = nested_json(100);
    assert_eq!(preflight_otlp_traces_json(&exact_depth), Ok(()));
    let over_depth = nested_json(127);
    assert_eq!(
        preflight_otlp_traces_json(&over_depth),
        Err(TraceReceiveFailure::ValueLimitExceeded)
    );

    let mut exact_body = br#"{"resourceSpans":[]}"#.to_vec();
    exact_body.resize(MAX_BYTES, b' ');
    assert_eq!(preflight_otlp_traces_json(&exact_body), Ok(()));
    exact_body.push(b' ');
    assert_eq!(
        preflight_otlp_traces_json(&exact_body),
        Err(TraceReceiveFailure::TransportLimitExceeded)
    );
}

#[test]
fn gzip_expansion_is_bounded_at_exact_and_one_over_decompressed_bytes() {
    let mut exact = Vec::with_capacity(MAX_BYTES);
    for _ in 0..(MAX_BYTES / 2) {
        exact.extend_from_slice(&[0x10, 0]);
    }
    assert_eq!(exact.len(), MAX_BYTES);
    let compressed = gzip(&exact);
    assert_eq!(preflight_otlp_traces_gzip(&compressed, false), Ok(()));
    exact.push(0);
    assert_eq!(
        preflight_otlp_traces_gzip(&gzip(&exact), false),
        Err(TraceReceiveFailure::TransportLimitExceeded)
    );

    let mut json = br#"{"resourceSpans":[]}"#.to_vec();
    json.resize(MAX_BYTES, b' ');
    assert_eq!(preflight_otlp_traces_gzip(&gzip(&json), true), Ok(()));
    json.push(b' ');
    assert_eq!(
        preflight_otlp_traces_gzip(&gzip(&json), true),
        Err(TraceReceiveFailure::TransportLimitExceeded)
    );
    assert_eq!(
        preflight_otlp_traces_gzip(&[0x1f, 0x8b, 0x08], true),
        Err(TraceReceiveFailure::MalformedCompression)
    );
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn nested_json(arrays: usize) -> Vec<u8> {
    let mut json = String::from(r#"{"unknown":["#);
    json.push_str(&"[".repeat(arrays));
    json.push('0');
    json.push_str(&"]".repeat(arrays));
    json.push_str("]}");
    json.into_bytes()
}
