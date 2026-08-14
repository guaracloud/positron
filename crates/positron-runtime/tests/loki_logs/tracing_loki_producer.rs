use std::error::Error;
use std::time::{Duration, SystemTime};

use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule, PolicyTarget};
use tracing_subscriber::layer::SubscriberExt;

use super::support::LiveLokiHarness;

#[tokio::test(flavor = "current_thread")]
async fn pinned_tracing_loki_exports_to_native_store_block() -> Result<(), Box<dyn Error>> {
    let policy = IngestPolicy::compile(
        67,
        [0x67; 32],
        vec![PolicyRule::new(
            "pinned-tracing-loki-truncate",
            Vec::new(),
            PolicyAction::TruncateBytes(PolicyTarget::body(), 16),
        )?],
    )?;
    let harness = LiveLokiHarness::start_with("tracing-loki-producer", |configuration| {
        configuration.with_ingest_policy(policy)
    })?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos(),
    )?;
    let endpoint = tracing_loki::url::Url::parse(&format!("http://{}", harness.loki_endpoint()?))?;
    let (layer, controller, background) = tracing_loki::builder()
        .label("producer", "tracing-loki-0.2.7")?
        .http_header("Authorization", format!("Bearer {}", harness.bearer()))?
        .build_controller_url(endpoint)?;
    let subscriber = tracing_subscriber::registry().with(layer);
    let task = tokio::spawn(background);

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(case = "m2-04", "produced-by-tracing-loki-0.2.7");
    });
    controller.shutdown().await;
    task.await?;

    let window = i64::try_from(Duration::from_secs(60).as_nanos())?;
    let start = now.checked_sub(window).ok_or("query start underflow")?;
    let end = now.checked_add(window).ok_or("query end overflow")?;
    let bodies =
        harness.query_log_bodies(&format!("logs | range query_time {start} {end} | limit 16"))?;
    assert!(
        !bodies.is_empty(),
        "pinned tracing-loki event was not queryable"
    );
    assert!(bodies.iter().all(|body| body.len() <= 16));
    Ok(())
}
