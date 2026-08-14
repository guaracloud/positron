use std::time::Duration;

use http::Request;
use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use tonic::Code;

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn saturated_authenticated_stream_rejects_before_payload_decode_and_releases_on_disconnect()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("pre-payload-admission")?;
    let endpoint = harness.endpoint();

    let stream = tokio::net::TcpStream::connect(endpoint).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let stalled = Request::builder()
        .method("POST")
        .uri("/opentelemetry.proto.collector.logs.v1.LogsService/Export")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", harness.bearer()))
        .body(())?;
    let (stalled_response, mut stalled_body) = sender.send_request(stalled, false)?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{endpoint}")),
    )
    .await??;
    let competing = harness.authorize(tonic::Request::new(otlp_request("must-not-decode")))?;
    let competing_result =
        tokio::time::timeout(Duration::from_secs(2), client.export(competing)).await;

    stalled_body.send_reset(h2::Reason::CANCEL);
    drop(stalled_body);
    drop(stalled_response);
    drop(sender);
    connection.abort();
    match connection.await {
        Ok(Ok(())) | Err(_) => {},
        Ok(Err(error)) => return Err(error.into()),
    }
    tokio::time::sleep(Duration::from_millis(25)).await;

    let competing_code = match competing_result {
        Ok(Err(failure)) => failure.code(),
        Ok(Ok(_)) => Code::Ok,
        Err(_) => Code::DeadlineExceeded,
    };
    if competing_code == Code::ResourceExhausted {
        let retry = harness.authorize(tonic::Request::new(otlp_request("capacity-released")))?;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.export(retry))
                .await??
                .into_inner()
                .partial_success
                .is_none()
        );
    }

    drop(client);
    let shutdown = harness.shutdown(ShutdownTrigger::DeadlineExpired).await?;
    assert_eq!(competing_code, Code::ResourceExhausted);
    assert_eq!(shutdown, positron_runtime::ExitOutcome::Forced);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn success_and_decode_failure_release_capacity_without_governor_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("admission-release")?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;

    for sequence in 0..8 {
        let request = harness.authorize(tonic::Request::new(otlp_request(&format!(
            "release-{sequence}"
        ))))?;
        let response =
            tokio::time::timeout(Duration::from_secs(2), client.export(request)).await??;
        assert!(response.into_inner().partial_success.is_none());
    }

    let mut malformed_payload = otlp_request("invalid-timestamp");
    malformed_payload
        .resource_logs
        .first_mut()
        .and_then(|resource| resource.scope_logs.first_mut())
        .and_then(|scope| scope.log_records.first_mut())
        .ok_or("test log record missing")?
        .time_unix_nano = u64::MAX;
    let malformed = harness.authorize(tonic::Request::new(malformed_payload))?;
    let malformed = tokio::time::timeout(Duration::from_secs(2), client.export(malformed))
        .await?
        .expect_err("out-of-range timestamp must be rejected");
    assert_eq!(malformed.code(), Code::InvalidArgument);

    let after_failure = harness.authorize(tonic::Request::new(otlp_request(
        "capacity-released-after-error",
    )))?;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.export(after_failure))
            .await??
            .into_inner()
            .partial_success
            .is_none()
    );

    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
