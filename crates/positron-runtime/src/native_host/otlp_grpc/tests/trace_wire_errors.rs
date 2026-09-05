use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message;

use super::trace_support::{
    Completion, ReceiverHarness, ScriptedBackend, gzip_trace_frame,
    gzip_trace_frame_with_span_count, profile_with_system_individual_value_bytes,
    profile_with_transport_limits, trace_frame, trace_frame_from_request, trace_request,
};

#[tokio::test(flavor = "current_thread")]
async fn malformed_trace_protobuf_has_stable_invalid_argument_status()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = ReceiverHarness::start(std::sync::Arc::new(ScriptedBackend::new([])))?;
    let (status, message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from_static(&[0, 0, 0, 0, 1, 0])),
    )
    .await?;
    assert_eq!(status, "3");
    assert_eq!(
        message.as_deref(),
        Some("OTLP%20Traces%20request%20was%20malformed")
    );
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_malformed_gzip_before_backend()
-> Result<(), Box<dyn std::error::Error>> {
    let mut frame = vec![1, 0, 0, 0, 4];
    frame.extend_from_slice(&[0, 1, 2, 3]);
    let profile = profile_with_transport_limits(frame.len(), 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, _message) = raw_trace_request_with_encoding(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
        Some("gzip"),
    )
    .await?;

    assert_eq!(status, "3");
    assert_eq!(
        _message.as_deref(),
        Some("OTLP%20Traces%20request%20was%20malformed")
    );
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_compressed_flag_without_gzip_encoding()
-> Result<(), Box<dyn std::error::Error>> {
    let frame = gzip_trace_frame(0x41)?;
    let profile = profile_with_transport_limits(frame.len(), 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, _message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "13");
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_an_invalid_compression_flag()
-> Result<(), Box<dyn std::error::Error>> {
    let mut frame = trace_frame(0x51)?;
    *frame.first_mut().ok_or("trace frame header missing")? = 2;
    let profile = profile_with_transport_limits(frame.len(), 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, _message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "13");
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_a_truncated_unary_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let mut frame = trace_frame(0x61)?;
    let declared_frame_length = frame.len();
    frame.pop();
    let profile = profile_with_transport_limits(declared_frame_length, 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, _message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "13");
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_uncompressed_payload_above_decompressed_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let frame = trace_frame(0x71)?;
    let payload_length = frame
        .len()
        .checked_sub(5)
        .ok_or("trace frame header missing")?;
    let profile = profile_with_transport_limits(
        frame.len(),
        payload_length
            .checked_sub(1)
            .ok_or("trace payload unexpectedly empty")?,
    )?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, _message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "8");
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_payload_over_system_value_limit_before_backend()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = trace_request(0x79).into_inner();
    let span = request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("trace fixture span missing")?;
    span.attributes.push(KeyValue {
        key: "over-system-limit".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::BytesValue(vec![0xa5; 65_537])),
        }),
        ..KeyValue::default()
    });
    let frame = trace_frame_from_request(request)?;
    let profile = profile_with_transport_limits(frame.len(), 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, _message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "3");
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_value_limit_status_names_class_and_magnitudes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut request = trace_request(0x7a).into_inner();
    let span = request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("trace fixture span missing")?;
    span.attributes.push(KeyValue {
        key: "short-key".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue("12345".to_owned())),
        }),
        ..KeyValue::default()
    });
    let frame = trace_frame_from_request(request)?;
    let profile = profile_with_system_individual_value_bytes(4);
    assert_eq!(
        profile
            .effective_limits()
            .dynamic_value()
            .individual_value_bytes()
            .value(),
        4
    );
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "3");
    assert_eq!(
        message.as_deref(),
        Some(
            "OTLP%20Traces%20request%20exceeded%20a%20value%20limit%20(individual%20value%20bytes:%20actual%205,%20allowed%204)",
        )
    );
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_reports_structural_limit_classes_and_magnitudes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut array_request = trace_request(0x7b).into_inner();
    let array_span = array_request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("array fixture span missing")?;
    array_span.attributes.push(KeyValue {
        key: "array".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: vec![AnyValue::default(); 1_025],
            })),
        }),
        ..KeyValue::default()
    });
    assert_trace_limit_status(
        array_request,
        "array%20entries:%20actual%201025,%20allowed%201024",
    )
    .await?;

    let mut list_request = trace_request(0x7c).into_inner();
    let list_span = list_request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("key/value-list fixture span missing")?;
    list_span.attributes.push(KeyValue {
        key: "key-value-list".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::KvlistValue(KeyValueList {
                values: (0..=1_024)
                    .map(|index| KeyValue {
                        key: format!("entry-{index}"),
                        ..KeyValue::default()
                    })
                    .collect(),
            })),
        }),
        ..KeyValue::default()
    });
    assert_trace_limit_status(
        list_request,
        "key/value-list%20entries:%20actual%201025,%20allowed%201024",
    )
    .await?;

    let mut aggregate_request = trace_request(0x7d).into_inner();
    let scopes = aggregate_request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .ok_or("aggregate fixture scope missing")?;
    let template = scopes
        .spans
        .first()
        .cloned()
        .ok_or("span template missing")?;
    scopes.spans = (0..5)
        .map(|span_index| Span {
            attributes: (0..1_024)
                .map(|attribute_index| KeyValue {
                    key: format!("attribute-{span_index}-{attribute_index}"),
                    ..KeyValue::default()
                })
                .collect(),
            ..template.clone()
        })
        .collect();
    assert_trace_limit_status(
        aggregate_request,
        "aggregate%20attribute%20count:%20actual%204097,%20allowed%204096",
    )
    .await?;
    Ok(())
}

async fn assert_trace_limit_status(
    request: ExportTraceServiceRequest,
    detail: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame = trace_frame_from_request(request)?;
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let (status, message) = raw_trace_request(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;
    assert_eq!(status, "3");
    let expected = format!("OTLP%20Traces%20request%20exceeded%20a%20value%20limit%20({detail})");
    assert_eq!(message.as_deref(), Some(expected.as_str()));
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_trace_route_has_stable_unimplemented_status()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = ReceiverHarness::start(std::sync::Arc::new(ScriptedBackend::new([])))?;
    let (status, message) = raw_trace_request(&harness, "/not-a-trace-route", None).await?;
    assert_eq!(status, "12");
    assert!(message.is_none());
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_gzip_trace_wire_body_uses_effective_compressed_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let frame = gzip_trace_frame(0x81)?;
    let exact = frame.len();
    let exact_profile = profile_with_transport_limits(exact, 1_048_576)?;
    let exact_backend = std::sync::Arc::new(ScriptedBackend::new([Completion::Committed]));
    let exact_harness = ReceiverHarness::start_with_profile(exact_backend.clone(), exact_profile)?;
    let (status, message) = raw_trace_request_with_encoding(
        &exact_harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame.clone())),
        Some("gzip"),
    )
    .await?;
    assert_eq!(status, "0", "exact wire body rejected: {message:?}");
    assert_eq!(exact_backend.calls(), 1);
    exact_harness.finish()?;

    let one_over_profile = profile_with_transport_limits(exact.saturating_sub(1), 1_048_576)?;
    let one_over_backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let one_over_harness =
        ReceiverHarness::start_with_profile(one_over_backend.clone(), one_over_profile)?;
    let (status, message) = raw_trace_request_with_encoding(
        &one_over_harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
        Some("gzip"),
    )
    .await?;
    assert_eq!(status, "8", "one-over wire body was accepted: {message:?}");
    assert_eq!(one_over_backend.calls(), 0);
    one_over_harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_gzip_trace_message_uses_effective_decompressed_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let frame = gzip_trace_frame_with_span_count(0x91, 8)?;
    let decompressed = {
        let body = trace_request(0x91).into_inner();
        let mut body = body;
        let template = body.resource_spans[0].scope_spans[0].spans[0].clone();
        body.resource_spans[0].scope_spans[0]
            .spans
            .extend(std::iter::repeat_n(template, 7));
        let body = body.encode_to_vec();
        body.len()
    };
    let exact_profile = profile_with_transport_limits(1_048_576, decompressed)?;
    let exact_backend = std::sync::Arc::new(ScriptedBackend::new([Completion::Committed]));
    let exact_harness = ReceiverHarness::start_with_profile(exact_backend.clone(), exact_profile)?;
    let (status, message) = raw_trace_request_with_encoding(
        &exact_harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame.clone())),
        Some("gzip"),
    )
    .await?;
    assert_eq!(status, "0", "exact message rejected: {message:?}");
    assert_eq!(exact_backend.calls(), 1);
    exact_harness.finish()?;

    let one_over_profile = profile_with_transport_limits(1_048_576, decompressed - 1)?;
    let one_over_backend = std::sync::Arc::new(ScriptedBackend::new([]));
    let one_over_harness =
        ReceiverHarness::start_with_profile(one_over_backend.clone(), one_over_profile)?;
    let (status, message) = raw_trace_request_with_encoding(
        &one_over_harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
        Some("gzip"),
    )
    .await?;
    assert_eq!(status, "8", "one-over message was accepted: {message:?}");
    assert_eq!(one_over_backend.calls(), 0);
    one_over_harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_gzip_trace_allows_compressed_frame_above_decompressed_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let (frame, decompressed) = incompressible_gzip_trace_frame(0xa1)?;
    let compressed = frame.len();
    assert!(compressed > decompressed);
    let profile = profile_with_transport_limits(compressed, decompressed)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, message) = raw_trace_request_with_encoding(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
        Some("gzip"),
    )
    .await?;

    assert_eq!(
        status, "0",
        "valid separately bounded request rejected: {message:?}"
    );
    assert_eq!(backend.calls(), 1);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_rejects_multiple_unary_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let mut body = trace_frame(0xb1)?;
    body.extend_from_slice(&trace_frame(0xc1)?);
    let profile = profile_with_transport_limits(body.len(), 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, message) = raw_trace_request_with_encoding(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(body)),
        None,
    )
    .await?;

    assert_eq!(
        status, "3",
        "multiple unary messages were accepted: {message:?}"
    );
    assert_eq!(backend.calls(), 0);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_trace_accepts_one_message_with_request_trailers()
-> Result<(), Box<dyn std::error::Error>> {
    let frame = trace_frame(0xc1)?;
    let profile = profile_with_transport_limits(frame.len(), 1_048_576)?;
    let backend = std::sync::Arc::new(ScriptedBackend::new([Completion::Committed]));
    let harness = ReceiverHarness::start_with_profile(backend.clone(), profile)?;

    let (status, message) = raw_trace_request_with_empty_trailers(
        &harness,
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        Some(Bytes::from(frame)),
    )
    .await?;

    assert_eq!(status, "0", "request trailers were rejected: {message:?}");
    assert_eq!(backend.calls(), 1);
    harness.finish()?;
    Ok(())
}

fn incompressible_gzip_trace_frame(
    seed: u8,
) -> Result<(Vec<u8>, usize), Box<dyn std::error::Error>> {
    let mut request = trace_request(seed).into_inner();
    let span = request
        .resource_spans
        .first_mut()
        .and_then(|resource| resource.scope_spans.first_mut())
        .and_then(|scope| scope.spans.first_mut())
        .ok_or("trace fixture span missing")?;
    let mut bytes = Vec::with_capacity(60_000);
    let mut value = u32::from(seed).wrapping_add(1);
    for _ in 0..60_000 {
        value = value.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push((value >> 24) as u8);
    }
    span.attributes.push(KeyValue {
        key: "incompressible".to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::BytesValue(bytes)),
        }),
        ..KeyValue::default()
    });
    let body = request.encode_to_vec();
    let decompressed = body.len();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut encoder, &body)?;
    let compressed = encoder.finish()?;
    let length = u32::try_from(compressed.len())?;
    let mut frame = Vec::with_capacity(compressed.len().saturating_add(5));
    frame.push(1);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&compressed);
    Ok((frame, decompressed))
}

async fn raw_trace_request(
    harness: &ReceiverHarness,
    path: &str,
    frame: Option<Bytes>,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    raw_trace_request_with_encoding(harness, path, frame, None).await
}

async fn raw_trace_request_with_encoding(
    harness: &ReceiverHarness,
    path: &str,
    frame: Option<Bytes>,
    grpc_encoding: Option<&str>,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    raw_trace_request_inner(harness, path, frame, grpc_encoding, false).await
}

async fn raw_trace_request_with_empty_trailers(
    harness: &ReceiverHarness,
    path: &str,
    frame: Option<Bytes>,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    raw_trace_request_inner(harness, path, frame, None, true).await
}

async fn raw_trace_request_inner(
    harness: &ReceiverHarness,
    path: &str,
    frame: Option<Bytes>,
    grpc_encoding: Option<&str>,
    request_trailers: bool,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let stream = tokio::net::TcpStream::connect(harness.endpoint).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let mut request_builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", harness.bearer));
    if let Some(grpc_encoding) = grpc_encoding {
        request_builder = request_builder.header("grpc-encoding", grpc_encoding);
    }
    let request = request_builder.body(())?;
    let end_stream = frame.is_none() && !request_trailers;
    let (response, mut body) = sender.send_request(request, end_stream)?;
    if let Some(frame) = frame {
        body.send_data(frame, !request_trailers)?;
    }
    if request_trailers {
        body.send_trailers(http::HeaderMap::new())?;
    }
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    let headers = response.headers().clone();
    let mut response_body = response.into_body();
    while let Some(chunk) = response_body.data().await {
        drop(chunk?);
    }
    let trailers = response_body.trailers().await?;
    let metadata = trailers.as_ref().unwrap_or(&headers);
    let status = metadata
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .ok_or("gRPC status missing")?
        .to_owned();
    let message = metadata
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    drop(sender);
    connection.abort();
    match connection.await {
        Ok(Ok(())) | Err(_) => {},
        Ok(Err(error)) => return Err(error.into()),
    }
    Ok((status, message))
}
