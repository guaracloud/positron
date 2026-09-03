use std::sync::Arc;
use std::time::Duration;

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use tonic::Code;

use super::trace_support::{Completion, ReceiverHarness, ScriptedBackend, trace_request};

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_statuses_preserve_retry_classes_and_release_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([
        Completion::Capacity,
        Completion::Retryable,
        Completion::Permanent,
        Completion::Ambiguous,
        Completion::Committed,
        Completion::Committed,
    ]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let capacity = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x11))?),
    )
    .await?
    .expect_err("capacity must be retryable");
    assert_eq!(capacity.code(), Code::ResourceExhausted);
    assert_eq!(
        capacity.message(),
        "OTLP Traces ingest capacity is unavailable"
    );
    assert_eq!(harness.snapshot()?, baseline);

    let retryable = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x21))?),
    )
    .await?
    .expect_err("storage failure must be retryable");
    assert_eq!(retryable.code(), Code::Unavailable);
    assert_eq!(
        retryable.message(),
        "OTLP Traces ingest is temporarily unavailable"
    );
    assert_eq!(harness.snapshot()?, baseline);

    let permanent = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x31))?),
    )
    .await?
    .expect_err("permanent rejection must not be retried");
    assert_eq!(permanent.code(), Code::InvalidArgument);
    assert_eq!(permanent.message(), "OTLP Traces request was rejected");
    assert_eq!(harness.snapshot()?, baseline);

    let ambiguous = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x41))?),
    )
    .await?
    .expect_err("post-commit failure must be explicit ambiguity");
    assert_eq!(ambiguous.code(), Code::Unavailable);
    assert_eq!(
        ambiguous.message(),
        "OTLP Traces commit outcome is ambiguous; retry may duplicate spans"
    );
    assert_eq!(backend.committed_records(), 1);
    assert_eq!(harness.snapshot()?, baseline);

    // The caller may lose the ambiguous response. A retry remains at-least-once
    // and is visible as a second committed observation in the native seam.
    let retry = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x41))?),
    )
    .await??;
    assert!(retry.into_inner().partial_success.is_none());
    assert_eq!(backend.committed_records(), 2);
    assert_eq!(harness.snapshot()?, baseline);

    let mut gzip_client = client
        .clone()
        .send_compressed(tonic::codec::CompressionEncoding::Gzip);
    let gzip = tokio::time::timeout(
        Duration::from_secs(2),
        gzip_client.export(harness.authorize_trace(trace_request(0x51))?),
    )
    .await??;
    assert!(gzip.into_inner().partial_success.is_none());
    assert_eq!(backend.committed_records(), 3);
    assert_eq!(harness.snapshot()?, baseline);

    drop(gzip_client);
    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_authentication_and_tenant_attribution_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let missing = tokio::time::timeout(Duration::from_secs(2), client.export(trace_request(0x61)))
        .await?
        .expect_err("missing credentials must be rejected");
    assert_eq!(missing.code(), Code::Unauthenticated);
    assert_eq!(
        missing.message(),
        "OTLP Traces request authentication was rejected"
    );

    let conflict = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace_with_tenant(trace_request(0x71), "other-tenant")?),
    )
    .await?
    .expect_err("tenant mismatch must be rejected");
    assert_eq!(conflict.code(), Code::Unauthenticated);
    assert_eq!(
        conflict.message(),
        "OTLP Traces request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_grpc_invalid_tenant_alias_is_rejected_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let rejected = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace_with_tenant(trace_request(0x79), "tenant#alias")?),
    )
    .await?
    .expect_err("invalid tenant aliases must fail authentication");
    assert_eq!(rejected.code(), Code::Unauthenticated);
    assert_eq!(
        rejected.message(),
        "OTLP Traces request authentication was rejected"
    );
    assert_eq!(backend.calls(), 0);
    assert_eq!(harness.snapshot()?, baseline);

    drop(client);
    harness.finish()?;
    Ok(())
}
