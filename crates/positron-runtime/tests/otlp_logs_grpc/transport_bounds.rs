use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{ExitOutcome, ShutdownTrigger};
use tonic::codec::CompressionEncoding;
use tonic::{Code, Request};

use super::support::{LiveGrpcHarness, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn gzip_is_supported_and_decompressed_messages_obey_the_receiver_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("gzip-bounds")?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??
    .send_compressed(CompressionEncoding::Gzip);

    let valid = harness.authorize(Request::new(otlp_request("gzip-valid")))?;
    let response = client.export(valid).await?.into_inner();
    assert!(response.partial_success.is_none());

    let expanded = "x".repeat(1_048_576);
    let excessive = harness.authorize(Request::new(otlp_request(&expanded)))?;
    let failure = client
        .export(excessive)
        .await
        .expect_err("decompression must stop at the receiver request ceiling");
    assert_eq!(failure.code(), Code::ResourceExhausted);
    assert_eq!(
        failure.message(),
        "Error decompressing: size limit, of 1048576 bytes, exceeded while decompressing message"
    );

    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
