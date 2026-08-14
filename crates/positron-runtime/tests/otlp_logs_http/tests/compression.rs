use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

#[test]
fn gzip_requests_have_semantic_parity_for_both_wire_encodings()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [HttpEncoding::Protobuf, HttpEncoding::Json] {
        let harness = LiveHttpHarness::start(encoding.label())?;
        let response = harness.export_gzip(encoding, otlp_request(encoding.label()))?;

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.header("content-type"),
            Some(encoding.content_type())
        );
        assert_eq!(
            harness.query_log_bodies("logs | range query_time 0 100 | limit 16")?,
            vec![encoding.label()]
        );
    }
    Ok(())
}
