use std::error::Error;

use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{AuthenticatedLokiPushRequest, LokiPushReceiver, ReceiveFailure};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[test]
fn protobuf_record_and_attribute_bounds_are_exact_and_labels_fail_closed()
-> Result<(), Box<dyn Error>> {
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

    let exact = admitted(authorize()?, governor, request(1_024, 0, "{}"))?;
    assert_eq!(
        LokiPushReceiver::new().decode(exact)?.records().len(),
        1_024
    );
    let over = admitted(authorize()?, governor, request(1_025, 0, "{}"))?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over)
            .expect_err("over protobuf record count"),
        ReceiveFailure::ValueLimitExceeded,
    );

    let exact = admitted(authorize()?, governor, request(1_024, 4, "{}"))?;
    assert_eq!(
        LokiPushReceiver::new().decode(exact)?.records().len(),
        1_024
    );
    let over = admitted(authorize()?, governor, request(1_024, 5, "{}"))?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(over)
            .expect_err("over protobuf aggregate attributes"),
        ReceiveFailure::ValueLimitExceeded,
    );

    let malformed = admitted(authorize()?, governor, request(1, 0, "{bad}"))?;
    assert_eq!(
        LokiPushReceiver::new()
            .decode(malformed)
            .expect_err("malformed stream label set"),
        ReceiveFailure::MalformedPayload,
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

fn admitted<'authority>(
    context: positron_governance::AuthorizedContext,
    governor: positron_kernel::ResourceGovernor<'authority>,
    request: PushRequest,
) -> Result<AuthenticatedLokiPushRequest<'authority>, Box<dyn Error>> {
    let compressed = snap::raw::Encoder::new().compress_vec(&request.encode_to_vec())?;
    Ok(AuthenticatedLokiPushRequest::snappy_protobuf(
        context, governor, compressed,
    )?)
}

fn request(records: usize, metadata_per_record: usize, labels: &str) -> PushRequest {
    let metadata = (0..metadata_per_record)
        .map(|ordinal| LabelPair {
            name: format!("key-{ordinal}"),
            value: "value".to_owned(),
        })
        .collect::<Vec<_>>();
    PushRequest {
        streams: vec![StreamAdapter {
            labels: labels.to_owned(),
            entries: (0..records)
                .map(|_| EntryAdapter {
                    timestamp: Some(Timestamp {
                        seconds: 1,
                        nanos: 2,
                    }),
                    line: "line".to_owned(),
                    structured_metadata: metadata.clone(),
                })
                .collect(),
        }],
    }
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

#[derive(Clone, Copy, PartialEq, Message)]
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
