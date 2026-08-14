use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use tonic::{Code, Request};

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn authentication_rejection_precedes_message_decompression_and_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("authentication")?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;
    let oversized_body = "x".repeat(4 * 1024 * 1024 + 1);

    let failure = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(Request::new(otlp_request(&oversized_body))),
    )
    .await?
    .expect_err("missing authorization must be rejected before the message-size boundary");

    assert_eq!(failure.code(), Code::Unauthenticated);
    assert_eq!(
        failure.message(),
        "OTLP Logs request authentication was rejected"
    );

    let mut conflicting = harness.authorize(Request::new(otlp_request(&oversized_body)))?;
    conflicting
        .metadata_mut()
        .insert("x-scope-orgid", "other-tenant".parse()?);
    let conflict = client
        .export(conflicting)
        .await
        .expect_err("a compatibility tenant conflict must fail before decoding");
    assert_eq!(conflict.code(), Code::Unauthenticated);
    assert_eq!(
        conflict.message(),
        "OTLP Logs request authentication was rejected"
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
