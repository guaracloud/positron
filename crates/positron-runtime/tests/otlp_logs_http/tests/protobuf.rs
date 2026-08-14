use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;
use prost::Message;

use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

#[test]
fn protobuf_export_commits_before_a_protocol_conformant_success()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("protobuf-success")?;
    let response = harness.export(HttpEncoding::Protobuf, otlp_request("http-protobuf"))?;

    assert_eq!(response.status(), 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/x-protobuf")
    );
    assert!(
        ExportLogsServiceResponse::decode(response.body())?
            .partial_success
            .is_none()
    );
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        vec!["http-protobuf"]
    );
    Ok(())
}
