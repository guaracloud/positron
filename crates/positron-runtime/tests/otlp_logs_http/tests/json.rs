use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceResponse;

use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

#[test]
fn json_export_preserves_native_semantics_and_negotiates_json_response()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("json-success")?;
    let response = harness.export(HttpEncoding::Json, otlp_request("http-json"))?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert!(
        serde_json::from_slice::<ExportLogsServiceResponse>(response.body())?
            .partial_success
            .is_none()
    );
    assert_eq!(
        harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
        vec!["http-json"]
    );
    Ok(())
}

#[test]
fn json_container_fanout_is_rejected_before_materializing_decode()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("json-preflight-fanout")?;
    let body = format!("{{\"resourceLogs\":[{}]}}", vec!["{}"; 1_025].join(","));
    let response = harness.export_body(HttpEncoding::Json, None, body.as_bytes())?;

    assert_eq!(response.status(), 400);
    assert_eq!(
        response.body(),
        br#"{"code":3,"message":"OTLP Logs request was rejected"}"#,
    );
    Ok(())
}
