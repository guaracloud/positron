use std::time::Duration;

use bytes::Bytes;
use http::Request;

use super::trace_support::{ReceiverHarness, ScriptedBackend};

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

async fn raw_trace_request(
    harness: &ReceiverHarness,
    path: &str,
    frame: Option<Bytes>,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    let stream = tokio::net::TcpStream::connect(harness.endpoint).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", harness.bearer))
        .body(())?;
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
