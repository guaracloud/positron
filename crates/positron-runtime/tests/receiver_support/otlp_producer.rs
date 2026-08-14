use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use opentelemetry::logs::{AnyValue, LogRecord as _, Logger, LoggerProvider};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;

mod otlp_http_client;

use otlp_http_client::SocketHttpClient;

pub(super) async fn export_one(
    endpoint: SocketAddr,
    path: &str,
    bearer: &str,
    body: &str,
) -> Result<(), Box<dyn Error>> {
    let mut headers = HashMap::new();
    headers.insert("authorization".to_owned(), format!("Bearer {bearer}"));
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("http://{endpoint}{path}"))
        .with_timeout(Duration::from_secs(2))
        .with_protocol(Protocol::HttpBinary)
        .with_headers(headers)
        .with_http_client(SocketHttpClient(endpoint))
        .build()?;
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    let logger = provider.logger("positron-live-http-producer-compatibility");
    let body = body.to_owned();

    tokio::task::spawn_blocking(move || {
        let mut record = logger.create_log_record();
        record.set_timestamp(SystemTime::UNIX_EPOCH + Duration::from_nanos(42));
        record.set_observed_timestamp(SystemTime::UNIX_EPOCH + Duration::from_nanos(84));
        record.set_body(AnyValue::String(body.into()));
        logger.emit(record);
        provider.shutdown()
    })
    .await??;
    Ok(())
}
