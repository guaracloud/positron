use std::time::Duration;

use super::trace_support::{Completion, ReceiverHarness, trace_frame, trace_request};
use bytes::Bytes;
use http::Request;
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
use std::sync::Arc;
use tonic::Code;

fn assert_reservation_ledger_unchanged(
    before: positron_kernel::ResourceSnapshot,
    after: positron_kernel::ResourceSnapshot,
) {
    assert_eq!(after.outstanding_total(), before.outstanding_total());
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(
            after.usage(dimension),
            before.usage(dimension),
            "resource usage drifted for {dimension:?}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_trace_worker_reports_capacity_before_decode_and_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(super::trace_support::ScriptedBackend::new([
        Completion::Stall,
        Completion::Committed,
    ]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;

    let mut first_client = client.clone();
    let first_request = harness.authorize_trace(trace_request(0xa1))?;
    let first = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), first_client.export(first_request)).await
    });
    let entered = tokio::time::timeout(Duration::from_secs(2), async {
        while !backend.stall_entered() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(entered.is_ok(), "trace worker did not enter the stall");

    let mut second_client = client.clone();
    let second_request = harness.authorize_trace(trace_request(0xb1))?;
    let second = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(2), second_client.export(second_request)).await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;

    let saturated = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0xc1))?),
    )
    .await?
    .expect_err("a full trace worker queue must refuse admission");
    assert_eq!(saturated.code(), Code::ResourceExhausted);
    assert_eq!(
        saturated.message(),
        "OTLP Traces ingest capacity is unavailable"
    );

    backend.release_stall();
    let first_result = first.await??;
    assert!(first_result.is_ok(), "stalled export did not complete");
    let second_result = second.await??;
    assert!(second_result.is_ok(), "queued export did not complete");
    assert_eq!(backend.calls(), 2);
    assert_reservation_ledger_unchanged(baseline, harness.snapshot()?);

    drop(client);
    harness.finish()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_trace_export_releases_worker_admission_for_the_next_export()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(super::trace_support::ScriptedBackend::new([
        Completion::Stall,
        Completion::Committed,
    ]));
    let harness = ReceiverHarness::start(backend.clone())?;
    let baseline = harness.snapshot()?;
    let stream = tokio::net::TcpStream::connect(harness.endpoint).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri("/opentelemetry.proto.collector.trace.v1.TraceService/Export")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {}", harness.bearer))
        .body(())?;
    let (response, mut body) = sender.send_request(request, false)?;
    body.send_data(Bytes::from(trace_frame(0x81)?), true)?;
    let entered = tokio::time::timeout(Duration::from_secs(2), async {
        while !backend.stall_entered() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    assert!(
        entered.is_ok(),
        "trace worker did not enter the stalled seam"
    );

    body.send_reset(h2::Reason::CANCEL);
    drop(body);
    drop(response);
    drop(sender);
    connection.abort();
    match connection.await {
        Ok(Ok(())) | Err(_) => {},
        Ok(Err(error)) => return Err(error.into()),
    }
    backend.release_stall();

    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        TraceServiceClient::connect(format!("http://{}", harness.endpoint)),
    )
    .await??;
    let retry = tokio::time::timeout(
        Duration::from_secs(2),
        client.export(harness.authorize_trace(trace_request(0x91))?),
    )
    .await??;
    assert!(retry.into_inner().partial_success.is_none());
    assert_eq!(harness.backend.calls(), 2);
    assert_reservation_ledger_unchanged(baseline, harness.snapshot()?);

    drop(client);
    harness.finish()?;
    Ok(())
}
