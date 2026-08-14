use std::error::Error;

use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule, PolicyTarget};

use super::support::LiveLokiHarness;

#[path = "../receiver_support/otlp_producer.rs"]
mod pinned_otlp;

#[tokio::test(flavor = "current_thread")]
async fn pinned_sdk_exports_over_loki_otlp_alias() -> Result<(), Box<dyn Error>> {
    let policy = IngestPolicy::compile(
        66,
        [0x66; 32],
        vec![PolicyRule::new(
            "pinned-loki-otlp-truncate",
            Vec::new(),
            PolicyAction::TruncateBytes(PolicyTarget::body(), 12),
        )?],
    )?;
    let harness = LiveLokiHarness::start_with("otlp-sdk-producer", |configuration| {
        configuration.with_ingest_policy(policy)
    })?;
    pinned_otlp::export_one(
        harness.loki_endpoint()?,
        "/otlp/v1/logs",
        harness.bearer(),
        "produced-by-pinned-sdk-on-loki-alias",
    )
    .await?;

    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["produced-by-"]
    );
    Ok(())
}
