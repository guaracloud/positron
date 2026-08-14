use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use std::time::Duration;
use tonic::Request;

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn authenticated_export_commits_before_success_and_is_queryable()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("authenticated-export")?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;
    let request = harness.authorize(Request::new(otlp_request("grpc-durable")))?;

    let response = tokio::time::timeout(Duration::from_secs(2), client.export(request))
        .await??
        .into_inner();

    assert!(response.partial_success.is_none());
    let bodies = harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?;
    assert_eq!(bodies, ["grpc-durable"]);
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn acknowledged_log_survives_process_drop_and_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = LiveGrpcHarness::start("crash-restart")?;
    let mut client = LogsServiceClient::connect(format!("http://{}", harness.endpoint())).await?;
    let request = harness.authorize(Request::new(otlp_request("survives-restart")))?;
    assert!(
        client
            .export(request)
            .await?
            .into_inner()
            .partial_success
            .is_none()
    );
    drop(client);

    harness.crash()?;
    harness.restart()?;
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["survives-restart"]
    );
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
