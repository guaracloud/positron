use std::time::Duration;

use http::Request;
use positron_runtime::{ExitOutcome, ShutdownTrigger};

use super::support::ForcedGrpcHarness;

#[tokio::test(flavor = "current_thread")]
async fn deadline_force_closes_a_stalled_authenticated_rpc_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    for trigger in [
        ShutdownTrigger::DeadlineExpired,
        ShutdownTrigger::SecondSignal,
    ] {
        force_stalled_rpc(trigger).await?;
    }
    Ok(())
}

async fn force_stalled_rpc(trigger: ShutdownTrigger) -> Result<(), Box<dyn std::error::Error>> {
    let harness = ForcedGrpcHarness::start(match trigger {
        ShutdownTrigger::SecondSignal => "forced-second-signal",
        ShutdownTrigger::DeadlineExpired => "forced-deadline",
        ShutdownTrigger::FirstSignal => return Err("forced helper received first signal".into()),
    })?;
    let endpoint = harness.endpoint();
    let bearer = harness.bearer().to_owned();

    let stream = tokio::net::TcpStream::connect(endpoint).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri("/opentelemetry.proto.collector.logs.v1.LogsService/Export")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("authorization", format!("Bearer {bearer}"))
        .body(())?;
    let (response, mut body) = sender.send_request(request, false)?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    harness.trigger(trigger)?;
    let bounded = harness.outcome_within(Duration::from_millis(250));
    let completed_boundedly = bounded.is_ok();

    body.send_reset(h2::Reason::CANCEL);
    drop(body);
    drop(response);
    drop(sender);
    connection.abort();
    match connection.await {
        Ok(Ok(())) | Err(_) => {},
        Ok(Err(error)) => return Err(error.into()),
    }
    let eventual = match bounded {
        Ok(outcome) => outcome,
        Err(_) => harness.outcome_within(Duration::from_secs(2))?,
    };

    assert!(
        completed_boundedly,
        "forced shutdown waited for the stalled RPC beyond its deadline"
    );
    assert_eq!(eventual, ExitOutcome::Forced);
    assert!(harness.finish()?);
    Ok(())
}
