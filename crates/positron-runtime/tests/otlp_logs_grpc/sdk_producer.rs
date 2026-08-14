use std::time::{Duration, SystemTime};

use opentelemetry::logs::{AnyValue, LogRecord as _, Logger, LoggerProvider};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use positron_runtime::{ExitOutcome, ShutdownTrigger};

use super::support::LiveGrpcHarness;

#[tokio::test(flavor = "current_thread")]
async fn pinned_sdk_exports_over_authenticated_live_otlp_grpc()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveGrpcHarness::start("sdk-producer")?;
    let mut metadata = opentelemetry_otlp::tonic_types::metadata::MetadataMap::new();
    metadata.insert(
        "authorization",
        format!("Bearer {}", harness.bearer()).parse()?,
    );
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(format!("http://{}", harness.endpoint()))
        .with_timeout(Duration::from_secs(2))
        .with_metadata(metadata)
        .build()?;
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    let logger = provider.logger("positron-live-producer-compatibility");

    tokio::task::spawn_blocking(move || {
        let mut record = logger.create_log_record();
        record.set_timestamp(SystemTime::UNIX_EPOCH + Duration::from_nanos(42));
        record.set_observed_timestamp(SystemTime::UNIX_EPOCH + Duration::from_nanos(84));
        record.set_body(AnyValue::String("produced-by-pinned-sdk".into()));
        logger.emit(record);
        provider.shutdown()
    })
    .await??;

    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["produced-by-pinned-sdk"]
    );
    assert_eq!(
        harness.shutdown(ShutdownTrigger::FirstSignal).await?,
        ExitOutcome::Graceful
    );
    Ok(())
}
