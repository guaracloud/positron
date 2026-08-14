use std::time::Duration;

use bytes::Bytes;
use http::Request;
use positron_runtime::{ExitOutcome, ShutdownTrigger};

use super::support::LiveGrpcHarness;

#[tokio::test(flavor = "current_thread")]
async fn authenticated_malformed_protobuf_has_stable_decode_status()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("malformed-protobuf")?;
    let stream = tokio::net::TcpStream::connect(harness.endpoint()).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri("/opentelemetry.proto.collector.logs.v1.LogsService/Export")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", harness.bearer()))
        .body(())?;
    let (response, mut body) = sender.send_request(request, false)?;
    body.send_data(Bytes::from_static(&[0, 0, 0, 0, 1, 0]), true)?;
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    let headers = response.headers().clone();
    let mut response_body = response.into_body();
    while let Some(chunk) = response_body.data().await {
        drop(chunk?);
    }
    let trailers = response_body.trailers().await?;
    let metadata = trailers.as_ref().unwrap_or(&headers);
    assert_eq!(
        metadata.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("3")
    );
    assert_eq!(
        metadata.get("grpc-message").and_then(|v| v.to_str().ok()),
        Some("OTLP%20Logs%20request%20was%20malformed")
    );

    drop(sender);
    connection.abort();
    match connection.await {
        Ok(Ok(())) | Err(_) => {},
        Ok(Err(error)) => return Err(error.into()),
    }
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
