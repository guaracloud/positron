use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, SystemTime};

use opentelemetry::logs::{AnyValue, LogRecord as _, Logger, LoggerProvider};
use opentelemetry_http::{Bytes, HttpClient, HttpError};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;

use super::support::{LiveHttpHarness, parse_response};

#[tokio::test(flavor = "current_thread")]
async fn pinned_sdk_exports_over_authenticated_live_otlp_http()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-sdk-producer")?;
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_owned(),
        format!("Bearer {}", harness.bearer()),
    );
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(format!("http://{}/v1/logs", harness.endpoint()))
        .with_timeout(Duration::from_secs(2))
        .with_protocol(Protocol::HttpBinary)
        .with_headers(headers)
        .with_http_client(SocketHttpClient(harness.endpoint()))
        .build()?;
    let provider = SdkLoggerProvider::builder()
        .with_simple_exporter(exporter)
        .build();
    let logger = provider.logger("positron-live-http-producer-compatibility");

    tokio::task::spawn_blocking(move || {
        let mut record = logger.create_log_record();
        record.set_timestamp(SystemTime::UNIX_EPOCH + Duration::from_nanos(42));
        record.set_observed_timestamp(SystemTime::UNIX_EPOCH + Duration::from_nanos(84));
        record.set_body(AnyValue::String("produced-by-pinned-http-sdk".into()));
        logger.emit(record);
        provider.shutdown()
    })
    .await??;

    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        ["produced-by-pinned-http-sdk"]
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct SocketHttpClient(SocketAddr);

impl Debug for SocketHttpClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SocketHttpClient")
    }
}

#[async_trait::async_trait]
impl HttpClient for SocketHttpClient {
    async fn send_bytes(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let mut stream = TcpStream::connect_timeout(&self.0, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut wire = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in &parts.headers {
            if name == http::header::HOST || name == http::header::CONTENT_LENGTH {
                continue;
            }
            wire.push_str(name.as_str());
            wire.push_str(": ");
            wire.push_str(value.to_str()?);
            wire.push_str("\r\n");
        }
        wire.push_str("\r\n");
        stream.write_all(wire.as_bytes())?;
        stream.write_all(&body)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let response =
            parse_response(&response).map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(http::Response::builder()
            .status(response.status())
            .body(Bytes::copy_from_slice(response.body()))?)
    }
}
