use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule, PolicyTarget};

use super::support::LiveHttpHarness;

#[path = "../../receiver_support/otlp_producer.rs"]
mod otlp_producer;

#[tokio::test(flavor = "current_thread")]
async fn pinned_sdk_exports_over_authenticated_live_otlp_http()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = IngestPolicy::compile(
        65,
        [0x65; 32],
        vec![PolicyRule::new(
            "pinned-http-truncate",
            Vec::new(),
            PolicyAction::TruncateBytes(PolicyTarget::body(), 12),
        )?],
    )?;
    let harness = LiveHttpHarness::start_with("http-sdk-producer", |configuration| {
        configuration.with_ingest_policy(policy)
    })?;
    otlp_producer::export_one(
        harness.endpoint(),
        "/v1/logs",
        harness.bearer(),
        "produced-by-pinned-http-sdk",
    )
    .await?;

    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["produced-by-"]
    );
    Ok(())
}
