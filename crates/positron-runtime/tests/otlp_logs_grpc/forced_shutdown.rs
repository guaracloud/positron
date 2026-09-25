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
    let client_cleanup = match connection.await {
        Ok(Ok(())) | Err(_) => Ok(()),
        Ok(Err(error)) => Err(error.into()),
    };
    let eventual = match bounded {
        Ok(outcome) => Ok(outcome),
        Err(_) => harness
            .outcome_within(Duration::from_secs(2))
            .map_err(Into::into),
    };

    finish_forced_rpc(
        completed_boundedly,
        eventual,
        client_cleanup,
        harness.finish(),
    )
}

fn finish_forced_rpc(
    completed_boundedly: bool,
    outcome: Result<ExitOutcome, Box<dyn std::error::Error>>,
    client_cleanup: Result<(), Box<dyn std::error::Error>>,
    ownership_released: Result<bool, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::new();
    if !completed_boundedly {
        failures.push("forced shutdown waited for the stalled RPC beyond its deadline".to_owned());
    }
    match outcome {
        Ok(ExitOutcome::Forced) => {},
        Ok(outcome) => failures.push(format!("forced shutdown exited as {outcome:?}")),
        Err(error) => failures.push(format!("forced shutdown did not complete: {error}")),
    }
    if let Err(error) = client_cleanup {
        failures.push(format!("stalled gRPC client cleanup failed: {error}"));
    }
    match ownership_released {
        Ok(true) => {},
        Ok(false) => failures.push("forced shutdown retained primary-volume ownership".to_owned()),
        Err(error) => failures.push(format!("forced shutdown server cleanup failed: {error}")),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}

#[test]
fn forced_shutdown_failure_reports_the_outcome_and_cleanup_failures() {
    let failure = finish_forced_rpc(
        false,
        Err(std::io::Error::other("outcome timeout").into()),
        Err(std::io::Error::other("client teardown").into()),
        Err(std::io::Error::other("server join").into()),
    )
    .expect_err("the original force result and both cleanup failures must remain visible");
    let message = failure.to_string();
    assert!(message.contains("outcome timeout"));
    assert!(message.contains("client teardown"));
    assert!(message.contains("server join"));
}
