use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_ingest::{
    IngestPolicy, PolicyAction, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
use positron_runtime::{ExitOutcome, ShutdownTrigger};

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn grpc_applies_the_shared_native_policy_before_persistence()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = IngestPolicy::compile(
        62,
        [0x62; 32],
        vec![PolicyRule::new(
            "grpc-truncate",
            vec![PolicyPredicate::receiver(PolicyReceiver::OtlpLogs)],
            PolicyAction::TruncateBytes(PolicyTarget::body(), 4),
        )?],
    )?;
    let harness = LiveGrpcHarness::start_with("policy", |configuration| {
        configuration.with_ingest_policy(policy)
    })?;
    let mut client = LogsServiceClient::connect(format!("http://{}", harness.endpoint())).await?;
    let response = client
        .export(harness.authorize(tonic::Request::new(otlp_request("sensitive")))?)
        .await?
        .into_inner();
    assert!(response.partial_success.is_none());
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["sens"]
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
