use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use positron_runtime::{ExitOutcome, ShutdownTrigger};

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn empty_export_succeeds_without_blocks_or_capacity_leak()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("empty-export")?;
    let mut client = LogsServiceClient::connect(format!("http://{}", harness.endpoint())).await?;
    let request = harness.authorize(tonic::Request::new(ExportLogsServiceRequest::default()))?;

    let response = client.export(request).await?.into_inner();

    assert!(response.partial_success.is_none());
    let follow_up = harness.authorize(tonic::Request::new(otlp_request("after-empty")))?;
    assert!(
        client
            .export(follow_up)
            .await?
            .into_inner()
            .partial_success
            .is_none()
    );
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        vec!["after-empty"]
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
