use std::error::Error;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::resource::v1::Resource;
use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestPolicy, OtlpLogsReceiver, PolicyAction,
    PolicyAttributePath, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
use prost::Message;

use super::policy_actions::{attributed_instance, ingest_and_scan};
use super::support::fixture;

#[test]
fn predicates_match_signal_receiver_service_severity_path_and_native_type()
-> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("predicate-policy")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let request = AuthenticatedOtlpLogsRequest::protobuf(
        context,
        fixture.authority.governor(),
        request().encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::new().decode(request)?;
    let secret = PolicyAttributePath::new(AttributeNamespace::Record, "secret.bytes")?;
    let policy = IngestPolicy::compile(
        25,
        vec![PolicyRule::new(
            "redact-warn-checkout-bytes",
            vec![
                PolicyPredicate::signal_store(SignalKind::Logs),
                PolicyPredicate::receiver(PolicyReceiver::OtlpGrpc),
                PolicyPredicate::service_identity("checkout")?,
                PolicyPredicate::log_severity(13),
                PolicyPredicate::attribute_type(secret.clone(), AttributeValueKind::Bytes),
            ],
            PolicyAction::Redact(PolicyTarget::attribute(secret)),
        )?],
    )?;
    let result = ingest_and_scan(&fixture, batch, &policy, 62)?;
    let record = result.records().first().ok_or("missing predicate match")?;
    let secret = record
        .attributes()
        .iter()
        .map(positron_signals::StoredLogAttribute::occurrences)
        .find(|attribute| attribute.key() == "secret.bytes")
        .and_then(|attribute| attribute.occurrence(0))
        .ok_or("missing redaction marker")?;
    assert!(secret.is_null());
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &["redact-warn-checkout-bytes"]
    );
    Ok(())
}

fn request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: vec![attribute("service.name", text("checkout"))],
                ..Resource::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    severity_number: 13,
                    attributes: vec![attribute("secret.bytes", bytes(vec![1, 2, 3]))],
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

fn bytes(value: Vec<u8>) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::BytesValue(value)),
    }
}
