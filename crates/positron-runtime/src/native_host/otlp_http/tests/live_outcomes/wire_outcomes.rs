use std::sync::Arc;

use super::super::super::ResponseEncoding;
use super::support::{HttpHarness, ScriptedBackend, decode_status, json_message, trace_body};

#[test]
fn live_http_trace_export_rejects_wire_failures_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = HttpHarness::start(backend)?;
    let baseline = harness.governor_snapshot()?.outstanding_total();

    let malformed_protobuf = harness.request(
        ResponseEncoding::Protobuf,
        vec![0x0a],
        None,
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(malformed_protobuf.status(), 400);
    assert_eq!(
        decode_status(&malformed_protobuf, ResponseEncoding::Protobuf).code,
        3
    );

    let malformed_json = harness.request(
        ResponseEncoding::Json,
        br#"{"resourceSpans":["#.to_vec(),
        None,
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(malformed_json.status(), 400);
    assert_eq!(
        decode_status(&malformed_json, ResponseEncoding::Json).code,
        3
    );

    let malformed_gzip = harness.request(
        ResponseEncoding::Json,
        vec![0x1f, 0x8b, 0x00],
        Some("gzip"),
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(malformed_gzip.status(), 400);
    assert_eq!(
        decode_status(&malformed_gzip, ResponseEncoding::Json).code,
        3
    );

    let unsupported_media = harness.request_with_content_type(
        "application/octet-stream",
        Vec::new(),
        None,
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(unsupported_media.status(), 415);
    assert_eq!(
        json_message(&unsupported_media)?,
        "OTLP Traces Content-Type is unsupported"
    );

    let unsupported_encoding = harness.request_with_content_type(
        "application/json",
        Vec::new(),
        Some("br"),
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(unsupported_encoding.status(), 415);
    assert_eq!(
        json_message(&unsupported_encoding)?,
        "OTLP Traces Content-Encoding is unsupported"
    );

    let missing_auth = harness.request(
        ResponseEncoding::Protobuf,
        trace_body(),
        None,
        None,
        None,
        None,
    )?;
    assert_eq!(missing_auth.status(), 401);
    assert_eq!(
        decode_status(&missing_auth, ResponseEncoding::Protobuf).code,
        16
    );

    let tenant_conflict = harness.request(
        ResponseEncoding::Protobuf,
        trace_body(),
        None,
        Some(&harness.bearer),
        Some("different-tenant"),
        None,
    )?;
    assert_eq!(tenant_conflict.status(), 401);
    assert_eq!(
        decode_status(&tenant_conflict, ResponseEncoding::Protobuf).code,
        16
    );

    let oversized = harness.request(
        ResponseEncoding::Protobuf,
        vec![0],
        None,
        Some(&harness.bearer),
        None,
        Some(1_048_577),
    )?;
    assert_eq!(oversized.status(), 413);
    assert_eq!(
        decode_status(&oversized, ResponseEncoding::Protobuf).code,
        8
    );

    let complete_body = trace_body();
    let truncated = harness.request(
        ResponseEncoding::Protobuf,
        complete_body.clone(),
        None,
        Some(&harness.bearer),
        None,
        Some(complete_body.len().saturating_add(1)),
    )?;
    assert_eq!(truncated.status(), 400);
    assert_eq!(
        decode_status(&truncated, ResponseEncoding::Protobuf).code,
        3
    );
    assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    assert_eq!(harness.backend_calls(), 0);
    Ok(())
}
