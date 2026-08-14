use std::time::Duration;

use bytes::Bytes;
use http::Request;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use prost::Message;

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn response_disconnect_then_retry_can_duplicate_a_durable_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("disconnect-retry")?;
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
    let protobuf = otlp_request("at-least-once").encode_to_vec();
    let length = u32::try_from(protobuf.len())?;
    let mut frame = Vec::with_capacity(protobuf.len().saturating_add(5));
    frame.push(0);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&protobuf);
    body.send_data(Bytes::from(frame), true)?;
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["at-least-once"]
    );
    let response_body = response.into_body();
    drop(response_body);
    drop(sender);
    connection.abort();
    match connection.await {
        Ok(Ok(())) | Err(_) => {},
        Ok(Err(error)) => return Err(error.into()),
    }

    let mut client = LogsServiceClient::connect(format!("http://{}", harness.endpoint())).await?;
    let retry = harness.authorize(tonic::Request::new(otlp_request("at-least-once")))?;
    assert!(
        client
            .export(retry)
            .await?
            .into_inner()
            .partial_success
            .is_none()
    );
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["at-least-once", "at-least-once"]
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
