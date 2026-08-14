use std::error::Error;
use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_runtime::ListenerRole;
use prost::Message;

use super::support;

#[test]
fn loki_otlp_alias_reuses_otlp_json_protobuf_gzip_and_auth_semantics() -> Result<(), Box<dyn Error>>
{
    let harness = support::LiveLokiHarness::start("otlp-alias")?;
    let request = request();
    let protobuf = request.encode_to_vec();
    let json = serde_json::to_vec(&request)?;
    let gzip_json = gzip(&json)?;

    for (content_type, content_encoding, body) in [
        ("application/x-protobuf", None, protobuf.as_slice()),
        ("application/json", None, json.as_slice()),
        ("application/json", Some("gzip"), gzip_json.as_slice()),
    ] {
        let mut headers = vec![
            ("Authorization", format!("Bearer {}", harness.bearer())),
            ("Content-Type", content_type.to_owned()),
        ];
        if let Some(content_encoding) = content_encoding {
            headers.push(("Content-Encoding", content_encoding.to_owned()));
        }
        let borrowed = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect::<Vec<_>>();
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/otlp/v1/logs",
                &borrowed,
                body,
            )?,
            200,
        );
    }

    support::assert_status(
        harness.http_with_advertised_length(
            ListenerRole::LokiPush,
            "POST",
            "/otlp/v1/logs",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/json"),
                ("X-Scope-OrgID", "other-tenant"),
            ],
            1_048_577,
        )?,
        401,
    );
    Ok(())
}

fn request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue("alias".to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn gzip(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}
