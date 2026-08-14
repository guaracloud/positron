use std::error::Error;
use std::time::{Duration, SystemTime};

use tracing_subscriber::layer::SubscriberExt;

use super::support::LiveLokiHarness;

#[tokio::test(flavor = "current_thread")]
async fn pinned_tracing_loki_exports_to_native_store_block() -> Result<(), Box<dyn Error>> {
    let harness = LiveLokiHarness::start("tracing-loki-producer")?;
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
        bodies
            .iter()
            .any(|body| body.contains("produced-by-tracing-loki-0.2.7")),
        "pinned tracing-loki event was not queryable: {bodies:?}"
    );
    Ok(())
}
