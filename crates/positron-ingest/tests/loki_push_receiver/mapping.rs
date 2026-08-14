use std::error::Error;

use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedLokiPushRequest, LokiPushReceiver, NativeLogCandidate};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[test]
fn json_push_maps_stream_and_metadata_without_losing_correlation() -> Result<(), Box<dyn Error>> {
    let roots = temporary_roots()?;
    let paths = BootstrapPaths::new(
        &roots.data(),
        &roots.secrets(),
        MountQualification::LocalHost,
    )?;
    InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let claim = InstanceBootstrap::claim(&paths)?;
    let instance = InstanceBootstrap::reopen(&paths)?;
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("missing ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let fixture = fixture(instance.default_tenant_id())?;
    let body = br#"{
        "streams":[{
            "stream":{"app":"api","trace_id":"00112233445566778899aabbccddeeff"},
            "values":[["1000000002","hello",{
                "attempt":"first",
                "span_id":"0102030405060708"
            }]]
        },{
            "stream":{"trace_id":"not-an-identifier"},
            "values":[["1000000003","invalid correlation stays source data"]]
        }]
    }"#;

    let request =
        AuthenticatedLokiPushRequest::json(context, fixture.authority.governor(), body.to_vec())?;
    let batch = LokiPushReceiver::new().decode(request)?;
    let record = batch.records().first().ok_or("missing mapped record")?;

    assert_eq!(batch.records().len(), 2);
    assert_eq!(batch.attribution().tenant_id(), fixture.tenant);
    assert_eq!(record.event_time_unix_nanos(), Some(1_000_000_002));
    assert_eq!(record.observed_time_unix_nanos(), None);
    assert_eq!(
        record.body(),
        Some(&CandidateAttributeValue::string("hello".to_owned()))
    );
    assert_string(record, AttributeNamespace::Stream, "app", "api")?;
    assert_string(
        record,
        AttributeNamespace::Stream,
        "trace_id",
        "00112233445566778899aabbccddeeff",
    )?;
    assert_string(record, AttributeNamespace::Record, "attempt", "first")?;
    assert_eq!(
        record.metadata().trace_id(),
        Some([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    );
    assert_eq!(
        record.metadata().span_id(),
        Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    );
    let invalid = batch
        .records()
        .get(1)
        .ok_or("missing invalid identifier record")?;
    assert_eq!(invalid.metadata().trace_id(), None);
    assert_string(
        invalid,
        AttributeNamespace::Stream,
        "trace_id",
        "not-an-identifier",
    )?;
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .outstanding_reservations(),
        1
    );
    drop(batch);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .outstanding_reservations(),
        0
    );
    Ok(())
}

#[test]
fn protobuf_push_decodes_raw_snappy_and_preserves_repeated_metadata() -> Result<(), Box<dyn Error>>
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
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("missing ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let fixture = fixture(instance.default_tenant_id())?;
    let protobuf = PushRequest {
        streams: vec![StreamAdapter {
            labels: r#"{app="api",empty="",escaped="\xC3\xA9",trace_id="00112233445566778899aabbccddeeff"}"#
                .to_owned(),
            entries: vec![EntryAdapter {
                timestamp: Some(Timestamp {
                    seconds: 1,
                    nanos: 2,
                }),
                line: "hello from protobuf".to_owned(),
                structured_metadata: vec![
                    LabelPair {
                        name: "attempt".to_owned(),
                        value: "first".to_owned(),
                    },
                    LabelPair {
                        name: "attempt".to_owned(),
                        value: "second".to_owned(),
                    },
                    LabelPair {
                        name: "span_id".to_owned(),
                        value: "0102030405060708".to_owned(),
                    },
                ],
            }],
        }],
    }
    .encode_to_vec();

    let request = AuthenticatedLokiPushRequest::snappy_protobuf(
        context,
        fixture.authority.governor(),
        raw_snappy_literal(&protobuf)?,
    )?;
    let batch = LokiPushReceiver::new().decode(request)?;
    let record = batch.records().first().ok_or("missing mapped record")?;

    assert_eq!(record.event_time_unix_nanos(), Some(1_000_000_002));
    assert_eq!(
        record.body(),
        Some(&CandidateAttributeValue::string(
            "hello from protobuf".to_owned()
        ))
    );
    let attempts = record
        .attributes()
        .iter()
        .find(|attribute| {
            attribute.namespace() == AttributeNamespace::Record && attribute.key() == "attempt"
        })
        .ok_or("missing repeated metadata")?;
    assert_eq!(
        attempts.occurrences(),
        [
            CandidateAttributeValue::string("first".to_owned()),
            CandidateAttributeValue::string("second".to_owned()),
        ]
    );
    assert_string(record, AttributeNamespace::Stream, "escaped", "é")?;
    assert!(
        !record
            .attributes()
            .iter()
            .any(
                |attribute| attribute.namespace() == AttributeNamespace::Stream
                    && attribute.key() == "empty"
            )
    );
    assert_eq!(
        record.metadata().trace_id(),
        Some([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    );
    assert_eq!(
        record.metadata().span_id(),
        Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    );
    drop(batch);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()?
            .outstanding_reservations(),
        0
    );
    Ok(())
}

fn assert_string(
    record: &NativeLogCandidate,
    namespace: AttributeNamespace,
    key: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let attribute = record
        .attributes()
        .iter()
        .find(|attribute| attribute.namespace() == namespace && attribute.key() == key)
        .ok_or_else(|| format!("missing {namespace:?}.{key}"))?;
    assert_eq!(
        attribute.occurrences(),
        [CandidateAttributeValue::string(expected.to_owned())]
    );
    Ok(())
}

fn raw_snappy_literal(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let length = u64::try_from(input.len())?;
    let mut encoded = Vec::new();
    let mut remaining = length;
    loop {
        let byte = u8::try_from(remaining & 0x7f)?;
        remaining >>= 7;
        encoded.push(if remaining == 0 { byte } else { byte | 0x80 });
        if remaining == 0 {
            break;
        }
    }
    let length_minus_one = input.len().checked_sub(1).ok_or("empty Snappy literal")?;
    if length_minus_one < 60 {
        encoded.push(u8::try_from(length_minus_one)? << 2);
    } else if u8::try_from(length_minus_one).is_ok() {
        encoded.push(60 << 2);
        encoded.push(u8::try_from(length_minus_one)?);
    } else {
        encoded.push(61 << 2);
        encoded.extend_from_slice(&u16::try_from(length_minus_one)?.to_le_bytes());
    }
    encoded.extend_from_slice(input);
    Ok(encoded)
}

#[derive(Clone, PartialEq, Message)]
struct PushRequest {
    #[prost(message, repeated, tag = "1")]
    streams: Vec<StreamAdapter>,
}

#[derive(Clone, PartialEq, Message)]
struct StreamAdapter {
    #[prost(string, tag = "1")]
    labels: String,
    #[prost(message, repeated, tag = "2")]
    entries: Vec<EntryAdapter>,
}

#[derive(Clone, PartialEq, Message)]
struct EntryAdapter {
    #[prost(message, optional, tag = "1")]
    timestamp: Option<Timestamp>,
    #[prost(string, tag = "2")]
    line: String,
    #[prost(message, repeated, tag = "3")]
    structured_metadata: Vec<LabelPair>,
}

#[derive(Clone, PartialEq, Message)]
struct Timestamp {
    #[prost(int64, tag = "1")]
    seconds: i64,
    #[prost(int32, tag = "2")]
    nanos: i32,
}

#[derive(Clone, PartialEq, Message)]
struct LabelPair {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}
