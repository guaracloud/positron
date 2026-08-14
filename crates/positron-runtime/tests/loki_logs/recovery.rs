use std::error::Error;

use positron_runtime::ListenerRole;

use super::support;

const QUERY: &str = "logs | range query_time 0 100 | limit 16";

#[test]
fn committed_push_survives_restart_and_retry_may_duplicate() -> Result<(), Box<dyn Error>> {
    let mut harness = support::LiveLokiHarness::start("restart-retry")?;
    let body = br#"{"streams":[{"stream":{"app":"recovery"},"values":[["42","survives"]]}]}"#;

    push(&harness, body)?;
    harness.crash()?;
    harness.restart()?;
    assert_eq!(harness.query_log_bodies(QUERY)?, ["survives"]);

    push(&harness, body)?;
    assert_eq!(harness.query_log_bodies(QUERY)?, ["survives", "survives"]);
    Ok(())
}

fn push(harness: &support::LiveLokiHarness, body: &[u8]) -> Result<(), Box<dyn Error>> {
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/json"),
            ],
            body,
        )?,
        204,
    );
    Ok(())
}
