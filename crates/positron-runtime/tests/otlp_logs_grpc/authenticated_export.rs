use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_query::QueryBudget;
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ServeConfiguration,
    ShutdownTrigger,
};
use std::time::Duration;
use tonic::Request;

use super::support::{TestRoots, address, bindings, otlp_request};

#[tokio::test(flavor = "current_thread")]
async fn authenticated_export_commits_before_success_and_is_queryable()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("export")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = positron_runtime::NativeHost::new(bindings(&roots, "g")?);
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
    let mut request = Request::new(otlp_request("grpc-durable"));
    request.metadata_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            claim.ingest_secret().ok_or("ingest secret missing")?
        )
        .parse()?,
    );

    let response = tokio::time::timeout(Duration::from_secs(2), client.export(request))
        .await??
        .into_inner();

    assert!(response.partial_success.is_none());
    let services = process
        .services()
        .ok_or("serving process omitted services")?;
    assert_eq!(
        format!("{services:?}"),
        "ServiceHandle { <authorized runtime services> }"
    );
    let bodies = services.query_log_bodies(
        claim.query_secret().ok_or("query secret missing")?,
        "logs | range query_time 0 100 | limit 16",
        QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
    )?;
    assert_eq!(bodies, ["grpc-durable"]);
    drop(client);
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
