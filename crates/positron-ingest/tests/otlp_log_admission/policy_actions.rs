use std::error::Error;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{
    AnyValue, ArrayValue, KeyValue, KeyValueList, any_value,
};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::AttributeNamespace;
use positron_governance::{CompatibilityHints, PresentedCredential, RequestedIntent};
use positron_ingest::{
    AuthenticatedOtlpLogsRequest, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver,
    PolicyAction, PolicyAttributePath, PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_signals::{LogScan, LogStore, ScanLimit, SchemaCatalog, SchemaPath};
use prost::Message;

use super::support::{fixture, temporary_roots};

#[path = "policy_actions/harness.rs"]
mod harness;
pub(super) use harness::{attributed_instance, ingest_and_scan};

#[test]
fn remove_erases_source_content_and_persists_typed_provenance() -> Result<(), Box<dyn Error>> {
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
    let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
        context,
        fixture.authority.governor(),
        request().encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::new().decode(request)?;
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "credentials.password")?;
    let policy = IngestPolicy::compile(
        21,
        vec![PolicyRule::new(
            "remove-password",
            vec![PolicyPredicate::attribute_exists(path.clone())],
            PolicyAction::Remove(PolicyTarget::attribute(path)),
        )?],
    )?;

    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let shard = VirtualShardId::new(31)?;
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
    )?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(500)));
    let schema = super::schema_support::session(&fixture)?;
    assert!(matches!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
            schema.clone(),
        )
        .accept(batch, StoreBlockIdentity::new([0x35; 16])?),
        IngestOutcome::Full(_)
    ));

    let result = LogStore::new().scan(
        fixture.authority.governor(),
        fixture.tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let record = result.records().first().ok_or("missing committed record")?;
    let removed = record
        .attributes()
        .iter()
        .map(positron_signals::StoredLogAttribute::occurrences)
        .find(|attribute| attribute.key() == "credentials.password");
    assert!(removed.is_none());
    let schema_checkpoint = schema.checkpoint()?;
    let discovered = SchemaCatalog::decode_catalog_object(schema_checkpoint.catalog_bytes())?;
    let removed_path = SchemaPath::root(
        AttributeNamespace::Record,
        "credentials.password".to_owned(),
    )?;
    assert!(discovered.entry(&removed_path).is_none());
    assert_eq!(discovered.overflow_record_count(), 0);
    assert_eq!(record.policy_provenance().generation(), 21);
    assert_eq!(record.policy_provenance().digest(), policy.digest());
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &["remove-password"]
    );
    let reconstructed = policy.reconstruct_actions(
        record.policy_provenance().generation(),
        record.policy_provenance().digest(),
        record.policy_provenance().applied_rules(),
    )?;
    assert!(matches!(
        reconstructed.as_slice(),
        [("remove-password", PolicyAction::Remove(_))]
    ));
    Ok(())
}

#[test]
fn ordered_rules_transform_repeated_and_nested_native_values() -> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("ordered-policy")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
        context,
        fixture.authority.governor(),
        nested_request().encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::new().decode(request)?;
    let repeated = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?.at_occurrence(1);
    let nested = PolicyAttributePath::new(AttributeNamespace::Record, "payload")?.key("token")?;
    let notes = PolicyAttributePath::new(AttributeNamespace::Record, "notes")?;
    let items = PolicyAttributePath::new(AttributeNamespace::Record, "items")?;
    let policy = IngestPolicy::compile(
        22,
        vec![
            PolicyRule::new(
                "redact-second-secret",
                vec![PolicyPredicate::attribute_exists(repeated.clone())],
                PolicyAction::Redact(PolicyTarget::attribute(repeated)),
            )?,
            PolicyRule::new(
                "remove-nested-token",
                vec![PolicyPredicate::attribute_exists(nested.clone())],
                PolicyAction::Remove(PolicyTarget::attribute(nested)),
            )?,
            PolicyRule::new(
                "truncate-notes",
                vec![PolicyPredicate::attribute_exists(notes.clone())],
                PolicyAction::TruncateBytes(PolicyTarget::attribute(notes), 5),
            )?,
            PolicyRule::new(
                "truncate-items",
                vec![PolicyPredicate::attribute_exists(items.clone())],
                PolicyAction::TruncateElements(PolicyTarget::attribute(items), 2),
            )?,
        ],
    )?;
    let result = ingest_and_scan(&fixture, batch, &policy, 32)?;
    let record = result
        .records()
        .first()
        .ok_or("missing transformed record")?;

    let secret = occurrence(record, "secret")?;
    assert_eq!(
        secret.occurrence(0).and_then(|value| value.as_str()),
        Some("keep")
    );
    assert!(secret.occurrence(1).is_some_and(|value| value.is_null()));
    let payload = occurrence(record, "payload")?
        .occurrence(0)
        .ok_or("payload disappeared")?;
    assert_eq!(payload.key_value_list_len(), Some(0));
    let notes = occurrence(record, "notes")?
        .occurrence(0)
        .ok_or("missing truncated notes")?;
    assert_eq!(notes.as_str(), Some("ol\u{00e1}-"));
    let items = occurrence(record, "items")?
        .occurrence(0)
        .ok_or("missing truncated array")?;
    assert_eq!(items.array_len(), Some(2));
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &[
            "redact-second-secret",
            "remove-nested-token",
            "truncate-notes",
            "truncate-items",
        ]
    );
    Ok(())
}

#[test]
fn ordered_accept_and_reject_stop_at_the_first_terminal_action() -> Result<(), Box<dyn Error>> {
    let (instance, context) = attributed_instance("terminal-policy")?;
    let fixture = fixture(instance.default_tenant_id())?;
    let request = AuthenticatedOtlpLogsRequest::otlp_grpc_protobuf(
        context,
        fixture.authority.governor(),
        bodies_request(&["first", "second"]).encode_to_vec(),
    )?;
    let batch = OtlpLogsReceiver::new().decode(request)?;
    let policy = IngestPolicy::compile(
        23,
        vec![
            PolicyRule::new(
                "accept-first",
                vec![
                    PolicyPredicate::signal_store(SignalKind::Logs),
                    PolicyPredicate::receiver(PolicyReceiver::OtlpGrpc),
                    PolicyPredicate::body_exact_text("first")?,
                ],
                PolicyAction::Accept,
            )?,
            PolicyRule::new(
                "reject-first-too-late",
                vec![PolicyPredicate::body_exact_text("first")?],
                PolicyAction::Reject,
            )?,
            PolicyRule::new(
                "reject-second",
                vec![PolicyPredicate::body_exact_text("second")?],
                PolicyAction::Reject,
            )?,
        ],
    )?;
    let result = ingest_and_scan(&fixture, batch, &policy, 42)?;
    let record = result
        .records()
        .first()
        .ok_or("accepted record was not committed")?;
    assert_eq!(record.body().and_then(|body| body.as_str()), Some("first"));
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &["accept-first"]
    );
    Ok(())
}

fn occurrence<'record>(
    record: &'record positron_signals::ScannedLogRecord,
    key: &str,
) -> Result<&'record positron_domain::value::AttributeOccurrenceSet, Box<dyn Error>> {
    record
        .attributes()
        .iter()
        .map(positron_signals::StoredLogAttribute::occurrences)
        .find(|attribute| {
            attribute.namespace() == AttributeNamespace::Record && attribute.key() == key
        })
        .ok_or_else(|| format!("missing record attribute {key}").into())
}

fn request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    body: Some(text("authenticated request")),
                    attributes: vec![
                        attribute("credentials.password", text("never-store-this")),
                        attribute("request.method", text("POST")),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn nested_request() -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    attributes: vec![
                        attribute("secret", text("keep")),
                        attribute("secret", text("erase")),
                        attribute(
                            "payload",
                            key_value_list(vec![attribute("token", text("secret"))]),
                        ),
                        attribute("notes", text("ol\u{00e1}-mundo")),
                        attribute("items", array(vec![text("a"), text("b"), text("c")])),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

pub(super) fn bodies_request(bodies: &[&str]) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: bodies
                    .iter()
                    .map(|body| LogRecord {
                        time_unix_nano: 42,
                        body: Some(text(body)),
                        ..LogRecord::default()
                    })
                    .collect(),
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
