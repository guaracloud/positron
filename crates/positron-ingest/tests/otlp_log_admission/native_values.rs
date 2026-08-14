use std::error::Error;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::{LogScan, LogStore, ScanLimit};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[test]
fn native_values_survive_authenticated_otlp_acknowledgement_and_reopen()
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
    let context = instance.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("missing ingest credential")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let fixture = fixture(instance.default_tenant_id())?;
    let request = AuthenticatedOtlpLogsRequest::protobuf(
        context,
        fixture.authority.governor(),
        native_request().encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::new().decode(request)?;

    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let shard = VirtualShardId::new(131)?;
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let protection_key = || SegmentProtectionKey::from_owned(Box::new([0xe4; 32]));
    let policy = IngestPolicy::preserving(17, [0xe5; 32])?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(500)));
    {
        let ledger =
            ActiveSegmentLedger::open(&fixture.authority, &catalog, scope, protection_key())?;
        let committed = match LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
        )
        .accept(batch, StoreBlockIdentity::new([0xe6; 16])?)
        {
            IngestOutcome::Full(committed) => committed,
            other => return Err(format!("expected durable acknowledgement, got {other:?}").into()),
        };
        assert_eq!(committed.records(), 1);
        assert_eq!(committed.receipt().position().value(), 1);
    }

    let reopened =
        ActiveSegmentLedger::open(&fixture.authority, &catalog, scope, protection_key())?;
    let result = LogStore::new().scan(
        fixture.authority.governor(),
        fixture.tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let record = result
        .records()
        .first()
        .ok_or("durable acknowledgement produced no readable record")?;
    let body = record.body().ok_or("nested body was not preserved")?;
    assert_eq!(body.kind(), AttributeValueKind::KeyValueList);
    let body_entry = body
        .key_value_entry(0)
        .ok_or("nested body entry was not preserved")?;
    assert_eq!(body_entry.key(), "items");
    let body_array = body_entry.value();
    assert_eq!(body_array.kind(), AttributeValueKind::Array);
    assert_eq!(
        body_array.array_entry(0).and_then(|value| value.as_bytes()),
        Some([0_u8, 255_u8].as_slice())
    );
    assert!(
        body_array
            .array_entry(1)
            .is_some_and(|value| value.is_null())
    );

    let resource = occurrence(record, AttributeNamespace::Resource, "same-key")?;
    assert_eq!(
        resource.occurrence(0).and_then(|value| value.as_str()),
        Some("resource")
    );
    let scope_value = occurrence(record, AttributeNamespace::InstrumentationScope, "same-key")?;
    assert_eq!(
        scope_value
            .occurrence(0)
            .and_then(|value| value.as_boolean()),
        Some(true)
    );
    let record_values = occurrence(record, AttributeNamespace::Record, "same-key")?;
    assert_eq!(record_values.len(), 2);
    assert_eq!(
        record_values
            .occurrence(0)
            .and_then(|value| value.as_signed_integer()),
        Some(-7)
    );
    assert_eq!(
        record_values
            .occurrence(1)
            .and_then(|value| value.as_bytes()),
        Some([7_u8, 8_u8].as_slice())
    );
    assert_eq!(record.policy_provenance().generation(), 17);
    assert!(result.complete());
    Ok(())
}

fn occurrence<'record>(
    record: &'record positron_signals::ScannedLogRecord,
    namespace: AttributeNamespace,
    key: &str,
) -> Result<&'record positron_domain::value::AttributeOccurrenceSet, Box<dyn Error>> {
    record
        .attributes()
        .iter()
        .map(positron_signals::StoredLogAttribute::occurrences)
        .find(|occurrences| occurrences.namespace() == namespace && occurrences.key() == key)
        .ok_or_else(|| format!("missing {namespace:?} attribute {key}").into())
}

fn native_request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![attribute("same-key", text("resource"))],
                ..Resource::default()
            }),
            scope_logs: vec![ScopeLogs {
                scope: Some(InstrumentationScope {
                    name: "native-model".to_owned(),
                    attributes: vec![attribute("same-key", boolean(true))],
                    ..InstrumentationScope::default()
                }),
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    observed_time_unix_nano: 84,
                    body: Some(key_value_list(vec![attribute(
                        "items",
                        array(vec![bytes(vec![0, 255]), AnyValue { value: None }]),
                    )])),
                    attributes: vec![
                        attribute("same-key", signed_integer(-7)),
                        attribute("same-key", bytes(vec![7, 8])),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..KeyValue::default()
    }
}

fn text(value: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(value.to_owned())),
    }
}

fn boolean(value: bool) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::BoolValue(value)),
    }
}

fn signed_integer(value: i64) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::IntValue(value)),
    }
}

fn bytes(value: Vec<u8>) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::BytesValue(value)),
    }
}

fn array(values: Vec<AnyValue>) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::ArrayValue(ArrayValue { values })),
    }
}

fn key_value_list(values: Vec<KeyValue>) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::KvlistValue(KeyValueList { values })),
    }
}
