use std::net::Ipv4Addr;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
use positron_runtime::{ExitOutcome, ShutdownTrigger, TrustedProxy};
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

#[tokio::test(flavor = "current_thread")]
async fn configured_proxy_metadata_keeps_the_grpc_bearer_authoritative()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = TrustedProxy::exact_peer(Ipv4Addr::LOCALHOST.into(), 1)?;
    let harness = LiveGrpcHarness::start_with_bindings("trusted-proxy", |bindings| {
        bindings.with_trusted_proxy(policy)
    })?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;

    let mut accepted = harness.authorize(Request::new(otlp_request("trusted-proxy-grpc")))?;
    let metadata = accepted.metadata_mut();
    metadata.insert("x-forwarded-for", "198.51.100.24".parse()?);
    metadata.insert("x-forwarded-user", "proxied-operator".parse()?);
    metadata.insert("x-forwarded-authorization", "Bearer pos_forged".parse()?);
    tokio::time::timeout(Duration::from_secs(2), client.export(accepted)).await??;
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["trusted-proxy-grpc"]
    );

    let mut wrong_hops = harness.authorize(Request::new(otlp_request("must-not-persist")))?;
    let metadata = wrong_hops.metadata_mut();
    metadata.insert("x-forwarded-for", "198.51.100.24, 198.51.100.25".parse()?);
    metadata.insert("x-forwarded-user", "proxied-operator".parse()?);
    let failure = tokio::time::timeout(Duration::from_secs(2), client.export(wrong_hops))
        .await?
        .expect_err("a wrong forwarded hop count must be rejected");
    assert_eq!(failure.code(), Code::Unauthenticated);
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["trusted-proxy-grpc"]
    );

    let mut conflicting_actor =
        harness.authorize(Request::new(otlp_request("must-not-persist")))?;
    let metadata = conflicting_actor.metadata_mut();
    metadata.insert("x-forwarded-for", "198.51.100.24".parse()?);
    metadata.insert("x-forwarded-user", "proxied-user".parse()?);
    metadata.insert("x-forwarded-service", "proxied-service".parse()?);
    let failure = tokio::time::timeout(Duration::from_secs(2), client.export(conflicting_actor))
        .await?
        .expect_err("conflicting proxy actors must be rejected");
    assert_eq!(failure.code(), Code::Unauthenticated);
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["trusted-proxy-grpc"]
    );

    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unconfigured_grpc_forwarded_metadata_cannot_supply_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("unconfigured-forwarded-metadata")?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;
    let mut request = harness.authorize(Request::new(otlp_request("own-bearer-only")))?;
    let metadata = request.metadata_mut();
    metadata.insert("x-forwarded-for", "198.51.100.24".parse()?);
    metadata.insert("x-forwarded-user", "forged-user".parse()?);
    metadata.insert("x-forwarded-authorization", "Bearer pos_forged".parse()?);
    tokio::time::timeout(Duration::from_secs(2), client.export(request)).await??;
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["own-bearer-only"]
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_forwarded_metadata_rejects_a_nonmatching_configured_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = TrustedProxy::exact_peer(Ipv4Addr::new(127, 0, 0, 2).into(), 1)?;
    let harness = LiveGrpcHarness::start_with_bindings("wrong-trusted-proxy", |bindings| {
        bindings.with_trusted_proxy(policy)
    })?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{}", harness.endpoint())),
    )
    .await??;
    let mut request = harness.authorize(Request::new(otlp_request("must-not-persist")))?;
    let metadata = request.metadata_mut();
    metadata.insert("x-forwarded-for", "198.51.100.24".parse()?);
    metadata.insert("x-forwarded-service", "proxy-service".parse()?);
    let failure = tokio::time::timeout(Duration::from_secs(2), client.export(request))
        .await?
        .expect_err("a nonmatching peer must not become a trusted proxy");
    assert_eq!(failure.code(), Code::Unauthenticated);
    assert!(
        harness
            .query_log_bodies("logs | range query_time 0 100 | limit 16")?
            .is_empty()
    );
    drop(client);
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
