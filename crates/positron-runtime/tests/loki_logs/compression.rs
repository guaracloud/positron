use std::error::Error;
use std::io::Write;

use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder};
use positron_runtime::ListenerRole;

use super::{producer, support};

#[test]
fn loki_push_accepts_current_json_and_snappy_protobuf_encodings() -> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("encodings")?;
    let json = br#"{"streams":[{"stream":{"app":"identity"},"values":[["42","identity"]]}]}"#;

    for (encoding, body) in [
        (None, json.to_vec()),
        (Some("gzip"), gzip(json)?),
        (Some("deflate"), deflate(json)?),
    ] {
        let mut headers = vec![
            ("Authorization", format!("Bearer {}", harness.bearer())),
            ("Content-Type", "application/json".to_owned()),
        ];
        if let Some(encoding) = encoding {
            headers.push(("Content-Encoding", encoding.to_owned()));
        }
        let borrowed = headers
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect::<Vec<_>>();
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &borrowed,
                &body,
            )?,
            204,
        );
    }

    let protobuf = producer::snappy_push("protobuf")?;
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &format!("Bearer {}", harness.bearer())),
                ("Content-Type", "application/x-protobuf"),
                ("Content-Encoding", "snappy"),
            ],
            &protobuf,
        )?,
        204,
    );
    Ok(())
}

fn gzip(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}

fn deflate(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}
