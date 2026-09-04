use std::time::Duration;

use bytes::Bytes;
use http::Request;
use prost::Message;

use super::trace_support::{
    Completion, ReceiverHarness, ScriptedBackend, gzip_trace_frame,
    gzip_trace_frame_with_span_count, profile_with_transport_limits, trace_request,
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
    let end_stream = frame.is_none();
    let (response, mut body) = sender.send_request(request, end_stream)?;
    if let Some(frame) = frame {
        body.send_data(frame, true)?;
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
