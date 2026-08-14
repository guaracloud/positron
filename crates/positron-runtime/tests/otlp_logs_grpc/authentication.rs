use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ServeConfiguration,
    ShutdownTrigger,
};
use tonic::{Code, Request};

use super::support::{TestRoots, address, bindings, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn authentication_rejection_precedes_message_decompression_and_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("authentication")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = positron_runtime::NativeHost::new(bindings(&roots, "auth")?);
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

    let mut conflicting = Request::new(otlp_request(&oversized_body));
    conflicting.metadata_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            claim.ingest_secret().ok_or("ingest secret missing")?
        )
        .parse()?,
    );
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
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
