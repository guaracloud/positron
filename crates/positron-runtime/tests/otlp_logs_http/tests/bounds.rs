use std::io::Write;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use prost::Message;

use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

#[test]
fn compressed_and_expanded_request_bounds_return_permanent_413()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-bounds")?;
    let over_limit = vec![0_u8; 1_048_577];
    let exact_limit = exact_protobuf_request(1_048_576)?;
    let _ = opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest::decode(
        exact_limit.as_slice(),
    )?;

    let exact_raw = harness.export_body(HttpEncoding::Protobuf, None, &exact_limit)?;
    assert_eq!(
        exact_raw.status(),
        200,
        "content-length={:?} body={:?}",
        exact_raw.header("content-length"),
        exact_raw.body()
    );

    let mut exact_encoder = GzEncoder::new(Vec::new(), Compression::fast());
    exact_encoder.write_all(&exact_limit)?;
    let exact_expanded = harness.export_body(
        HttpEncoding::Protobuf,
        Some("gzip"),
        &exact_encoder.finish()?,
    )?;
    assert_eq!(exact_expanded.status(), 200);

    let compressed = harness.export_body(HttpEncoding::Protobuf, None, &over_limit)?;
    assert_eq!(compressed.status(), 413);
    assert_eq!(
        compressed.header("content-type"),
        Some(HttpEncoding::Protobuf.content_type())
    );

    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&over_limit)?;
    let expanded = harness.export_body(HttpEncoding::Json, Some("gzip"), &encoder.finish()?)?;
    assert_eq!(expanded.status(), 413);
    assert_eq!(
        expanded.header("content-type"),
        Some(HttpEncoding::Json.content_type())
    );
    Ok(())
}

#[test]
fn accepted_http_stream_blocks_until_the_existing_body_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = LiveHttpHarness::start("http-stalled-body")?;
    let (response, elapsed) = harness.request_stalled(1)?;

    assert_eq!(response.status(), 400);
    assert!(
        elapsed < Duration::from_secs(4),
        "stalled request exceeded the bounded connection timeout: {elapsed:?}"
    );
    Ok(())
}

fn exact_protobuf_request(length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut request = otlp_request("exact-boundary").encode_to_vec();
    let available = length
        .checked_sub(request.len())
        .ok_or("exact request fixture exceeds target")?;
    let payload_length = (0..=available)
        .find(|candidate| 1 + prost::length_delimiter_len(*candidate) + candidate == available)
        .ok_or("exact protobuf padding could not be represented")?;
    request.push(0x7a);
    prost::encode_length_delimiter(payload_length, &mut request)?;
    request.resize(length, 0);
    Ok(request)
}
