use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use prost::Message;

use super::support::{HttpEncoding, LiveHttpHarness};

#[test]
fn empty_exports_succeed_in_both_otlp_encodings() -> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-empty")?;
    for encoding in [HttpEncoding::Protobuf, HttpEncoding::Json] {
        let response = harness.export(encoding, ExportLogsServiceRequest::default())?;
        assert_eq!(response.status(), 200, "encoding={}", encoding.label());
        let decoded = match encoding {
            HttpEncoding::Protobuf => ExportLogsServiceResponse::decode(response.body())?,
            HttpEncoding::Json => serde_json::from_slice(response.body())?,
        };
        assert_eq!(decoded, ExportLogsServiceResponse::default());
    }
    Ok(())
}
