use std::error::Error;
use std::io::Write;

use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedLokiPushRequest, LokiPushReceiver, ReceiveFailure};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};

use super::support::{fixture, temporary_roots};

const BYTE_LIMIT: usize = 1_048_576;

#[test]
fn compressed_and_expanded_byte_bounds_are_exact_and_release_capacity() -> Result<(), Box<dyn Error>>
{
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let ingest_secret = claim.ingest_secret().ok_or("missing credential")?;
    let authorize = || {
        let credential = PresentedCredential::parse(ingest_secret)?;
        instance.attribute(
            credential,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )
    };
    let fixture = fixture(instance.default_tenant_id())?;
    let governor = fixture.authority.governor();

    let exact = AuthenticatedLokiPushRequest::json(authorize()?, governor, vec![b' '; BYTE_LIMIT])?;
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    drop(exact);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    let over_compressed =
        AuthenticatedLokiPushRequest::json(authorize()?, governor, vec![b' '; BYTE_LIMIT + 1])
            .err()
            .ok_or("over compressed bound was accepted")?;
    assert_eq!(over_compressed, ReceiveFailure::TransportLimitExceeded);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);

    let exact_body = exact_json(BYTE_LIMIT)?;
    let exact =
        AuthenticatedLokiPushRequest::gzip_json(authorize()?, governor, gzip(&exact_body)?)?;
    let batch = LokiPushReceiver::new().decode(exact)?;
    assert_eq!(batch.records().len(), 1);
    drop(batch);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);

    let over_json = exact_json(BYTE_LIMIT + 1)?;
    let over = AuthenticatedLokiPushRequest::gzip_json(authorize()?, governor, gzip(&over_json)?)?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over)
            .expect_err("over expanded bound"),
        ReceiveFailure::TransportLimitExceeded,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);

    let exact_deflate =
        AuthenticatedLokiPushRequest::deflate_json(authorize()?, governor, deflate(&exact_body)?)?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(exact_deflate)?
            .records()
            .len(),
        1
    );
    let over_deflate =
        AuthenticatedLokiPushRequest::deflate_json(authorize()?, governor, deflate(&over_json)?)?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over_deflate)
            .expect_err("over deflate expanded bound"),
        ReceiveFailure::TransportLimitExceeded,
    );

    let exact_snappy = snap::raw::Encoder::new().compress_vec(&vec![0_u8; BYTE_LIMIT])?;
    let exact_snappy =
        AuthenticatedLokiPushRequest::snappy_protobuf(authorize()?, governor, exact_snappy)?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(exact_snappy)
            .expect_err("zero protobuf should be malformed after exact expansion"),
        ReceiveFailure::MalformedPayload,
    );
    let over_snappy = AuthenticatedLokiPushRequest::snappy_protobuf(
        authorize()?,
        governor,
        snappy_declared_length(BYTE_LIMIT + 1)?,
    )?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over_snappy)
            .expect_err("over Snappy expanded bound"),
        ReceiveFailure::TransportLimitExceeded,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);

    let exact_streams =
        AuthenticatedLokiPushRequest::json(authorize()?, governor, json_streams(1_024))?;
    assert!(
        LokiPushReceiver::new()
            .decode(exact_streams)?
            .records()
            .is_empty()
    );
    let over_streams =
        AuthenticatedLokiPushRequest::json(authorize()?, governor, json_streams(1_025))?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over_streams)
            .expect_err("over empty-stream amplification"),
        ReceiveFailure::ValueLimitExceeded,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn structural_record_and_attribute_bounds_are_exact() -> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let fixture = fixture(instance.default_tenant_id())?;
    let ingest_secret = claim.ingest_secret().ok_or("missing credential")?;
    let authorize = || {
        let credential = PresentedCredential::parse(ingest_secret)?;
        instance.attribute(
            credential,
            RequestedIntent::Ingest,
            CompatibilityHints::none(),
        )
    };
    let governor = fixture.authority.governor();

    let exact =
        AuthenticatedLokiPushRequest::json(authorize()?, governor, json_records(1_024, false))?;
    assert_eq!(
        LokiPushReceiver::new().decode(exact)?.records().len(),
        1_024
    );
    let over =
        AuthenticatedLokiPushRequest::json(authorize()?, governor, json_records(1_025, false))?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over)
            .expect_err("over record count"),
        ReceiveFailure::ValueLimitExceeded,
    );

    let exact =
        AuthenticatedLokiPushRequest::json(authorize()?, governor, json_records(1_024, true))?;
    assert_eq!(
        LokiPushReceiver::new().decode(exact)?.records().len(),
        1_024
    );
    let mut over = String::from(
        "{\"streams\":[{\"stream\":{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\",\"d\":\"4\"},\"values\":[[\"1\",\"x\",{\"e\":\"5\"}]",
    );
    for _ in 1..1_024 {
        over.push_str(",[\"1\",\"x\"]");
    }
    over.push_str("]}]}");
    let over = AuthenticatedLokiPushRequest::json(authorize()?, governor, over.into_bytes())?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over)
            .expect_err("over aggregate attributes"),
        ReceiveFailure::ValueLimitExceeded,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

fn exact_json(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let prefix = br#"{"padding":""#;
    let suffix = br#"","streams":[{"stream":{"app":"test"},"values":[["1","line"]]}]}"#;
    let fill = length
        .checked_sub(prefix.len())
        .and_then(|value| value.checked_sub(suffix.len()))
        .ok_or("requested JSON length is too small")?;
    let mut json = Vec::with_capacity(length);
    json.extend_from_slice(prefix);
    json.resize(json.len() + fill, b'x');
    json.extend_from_slice(suffix);
    assert_eq!(json.len(), length);
    Ok(json)
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

fn snappy_declared_length(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut remaining = u64::try_from(length)?;
    let mut encoded = Vec::new();
    loop {
        let byte = u8::try_from(remaining & 0x7f)?;
        remaining >>= 7;
        encoded.push(if remaining == 0 { byte } else { byte | 0x80 });
        if remaining == 0 {
            return Ok(encoded);
        }
    }
}

fn json_records(records: usize, attributes: bool) -> Vec<u8> {
    let stream = if attributes {
        "{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\",\"d\":\"4\"}"
    } else {
        "{\"app\":\"test\"}"
    };
    let values = std::iter::repeat_n("[\"1\",\"x\"]", records)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"streams\":[{{\"stream\":{stream},\"values\":[{values}]}}]}}").into_bytes()
}

fn json_streams(streams: usize) -> Vec<u8> {
    let streams = std::iter::repeat_n(r#"{"stream":{"app":"test"},"values":[]}"#, streams)
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"streams":[{streams}]}}"#).into_bytes()
}
