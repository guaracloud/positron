use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ServeConfiguration,
    ShutdownTrigger,
};
use tonic::codec::CompressionEncoding;
use tonic::{Code, Request};

use super::support::{TestRoots, address, bindings, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn gzip_is_supported_and_decompressed_messages_obey_the_receiver_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("gzip-bounds")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let bearer = claim.ingest_secret().ok_or("ingest secret missing")?;
    let host = positron_runtime::NativeHost::new(bindings(&roots, "gzip")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::OtlpGrpc,
    )?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{endpoint}")),
    )
    .await??
    .send_compressed(CompressionEncoding::Gzip);

    let mut valid = Request::new(otlp_request("gzip-valid"));
    valid
        .metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse()?);
    let response = client.export(valid).await?.into_inner();
    assert!(response.partial_success.is_none());

    let expanded = "x".repeat(1_048_576);
    let mut excessive = Request::new(otlp_request(&expanded));
    excessive
        .metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse()?);
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
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
