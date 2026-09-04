use std::error::Error;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind, MarkerAction};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyAttributePath, PolicyRule, PolicyTarget};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, OrdinaryPool, ResourceDimension, SegmentScope,
};
use positron_signals::{LogScan, LogStore, ScanLimit, TraceScan, TraceStore};
use prost::Message;

use super::super::{ResponseEncoding, receive, receive_traces};
use crate::native_host::native_http::RequestHead;
use crate::{
    BootstrapPaths, InitializationPlan, InitializedInstance, InstanceBootstrap, ServiceHandle,
};

#[test]
fn authenticated_http_log_marker_survives_ack_and_runtime_reopen() -> Result<(), Box<dyn Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let (administrator_secret, bearer) = {
        let claim = InstanceBootstrap::claim(&paths)?;
        (
            claim.secret().to_owned(),
            claim
                .ingest_secret()
                .ok_or("ingest secret missing")?
                .to_owned(),
        )
    };
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let administrator = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-body",
            Vec::new(),
            PolicyAction::Redact(PolicyTarget::body()),
        )?],
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb7; 16])?,
        policy.clone(),
    )?;

    let body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    body: Some(string_value("log-body")),
                    attributes: vec![
                        attribute("secret", string_value("source-secret")),
                        attribute("null", AnyValue { value: None }),
                        attribute("lookalike", string_value("[REDACTED]")),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/logs".to_owned(),
            content_length: body.len(),
            bearer: Some(bearer.clone()),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
        },
        &services,
    )
    .map_err(|_| "log HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportLogsServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());
    drop(client);
    drop(services);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_log_marker(&reopened, &policy)?;
    Ok(())
}

#[test]
fn authenticated_http_log_attribute_marker_reports_insufficient_governor_headroom()
-> Result<(), Box<dyn Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let (administrator_secret, bearer) = {
        let claim = InstanceBootstrap::claim(&paths)?;
        (
            claim.secret().to_owned(),
            claim
                .ingest_secret()
                .ok_or("ingest secret missing")?
                .to_owned(),
        )
    };
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let administrator = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-secret",
            Vec::new(),
            PolicyAction::Redact(PolicyTarget::attribute(path)),
        )?],
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xba; 16])?,
        policy.clone(),
    )?;

    let before = initialized.resource_governor().inspect()?;
    assert_eq!(
        before.ordinary_capacity(ResourceDimension::CpuWorkUnits),
        32,
        "the runtime bootstrap contract fixes ordinary CPU capacity"
    );
    assert_eq!(
        before.pool_capacity(OrdinaryPool::Shared, ResourceDimension::CpuWorkUnits),
        12,
        "ordinary pool policy reserves 8+6+4+2 CPU units"
    );
    assert_eq!(
        before.pool_capacity(OrdinaryPool::Ingest, ResourceDimension::CpuWorkUnits),
        6,
        "ingest class headroom is fixed by the runtime bootstrap policy"
    );
    let body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    attributes: vec![
                        attribute("secret", string_value("source-secret")),
                        attribute("null", AnyValue { value: None }),
                        attribute("lookalike", string_value("[REDACTED]")),
                    ],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/logs".to_owned(),
            content_length: body.len(),
            bearer: Some(bearer.clone()),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
        },
        &services,
    )
    .map_err(|_| "log HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportLogsServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());

    // A source-shaped record near the bounded native value limit must retain
    // the typed retry outcome: candidate-aware admission is not a universal
    // capacity exemption for expensive policy work.
    let expensive_value = "x".repeat(500_000);
    let expensive_body = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    attributes: vec![attribute("secret", string_value(&expensive_value))],
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
    .encode_to_vec();
    let expensive_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let expensive_endpoint = expensive_listener.local_addr()?;
    let mut expensive_client = TcpStream::connect(expensive_endpoint)?;
    let (mut expensive_server, _) = expensive_listener.accept()?;
    expensive_client.write_all(&expensive_body)?;
    let expensive_response = receive(
        &mut expensive_server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/logs".to_owned(),
            content_length: expensive_body.len(),
            bearer: Some(bearer),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
        },
        &services,
    )
    .map_err(|_| "expensive log HTTP response was rejected")?;
    assert_eq!(expensive_response.status(), 429);
    assert_eq!(expensive_response.retry_after_seconds(), Some(1));
    drop(expensive_client);
    drop(client);
    drop(services);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_log_attribute_marker(&reopened, &policy)?;
    Ok(())
}

#[test]
fn authenticated_http_trace_marker_survives_ack_and_runtime_reopen() -> Result<(), Box<dyn Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let (administrator_secret, bearer) = {
        let claim = InstanceBootstrap::claim(&paths)?;
        (
            claim.secret().to_owned(),
            claim
                .ingest_secret()
                .ok_or("ingest secret missing")?
                .to_owned(),
        )
    };
    let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let administrator = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let path = PolicyAttributePath::new(AttributeNamespace::Record, "secret")?;
    let policy = IngestPolicy::compile(
        2,
        vec![PolicyRule::new(
            "redact-secret",
            Vec::new(),
            PolicyAction::Redact(PolicyTarget::attribute(path)),
        )?],
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        administrator,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb8; 16])?,
        policy.clone(),
    )?;

    let body = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x41; 16],
                    span_id: vec![0x42; 8],
                    name: "http-marker".to_owned(),
                    attributes: vec![attribute("secret", string_value("source-secret"))],
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive_traces(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
            content_length: body.len(),
            bearer: Some(bearer.clone()),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
        },
        &services,
    )
    .map_err(|_| "trace HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportTraceServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());

    let expensive_value = "x".repeat(65_536);
    let expensive_attributes = (0..8)
        .map(|_| attribute("secret", string_value(&expensive_value)))
        .collect();
    let expensive_body = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x43; 16],
                    span_id: vec![0x44; 8],
                    name: "expensive-http-marker".to_owned(),
                    attributes: expensive_attributes,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();
    let expensive_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let expensive_endpoint = expensive_listener.local_addr()?;
    let mut expensive_client = TcpStream::connect(expensive_endpoint)?;
    let (mut expensive_server, _) = expensive_listener.accept()?;
    expensive_client.write_all(&expensive_body)?;
    let expensive_response = receive_traces(
        &mut expensive_server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
            content_length: expensive_body.len(),
            bearer: Some(bearer),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
        },
        &services,
    )
    .map_err(|_| "expensive trace HTTP response was rejected")?;
    assert_eq!(expensive_response.status(), 429);
    assert_eq!(expensive_response.retry_after_seconds(), Some(1));
    drop(expensive_client);
    drop(client);
    drop(services);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_trace_marker(&reopened, &policy)?;
    Ok(())
}

fn assert_trace_marker(
    initialized: &InitializedInstance,
    policy: &IngestPolicy,
) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let basis = catalog.pin()?;
    let scope = basis
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Traces)?
        .into_iter()
        .next()
        .ok_or("trace scope missing after authenticated export")?;
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(
        &initialized._authority,
        &catalog,
        SegmentScope::new(initialized.tenant, SignalKind::Traces, scope.shard_id()),
        protection,
    )?;
    let result = TraceStore::new().scan(
        initialized.resource_governor(),
        initialized.tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    let observation = result
        .observations()
        .first()
        .ok_or("authenticated export did not persist a span")?
        .observation();
    let value = observation
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == "secret")
        .and_then(|attribute| attribute.occurrence(0))
        .ok_or("trace marker attribute missing")?;
    assert_eq!(value.marker_action(), Some(MarkerAction::Redacted));
    assert_eq!(
        value.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert_eq!(value.as_str(), None);
    assert_eq!(
        observation.policy_provenance().generation(),
        policy.generation()
    );
    assert_eq!(observation.policy_provenance().digest(), policy.digest());
    assert_eq!(
        observation.policy_provenance().applied_rules(),
        &["redact-secret"]
    );
    Ok(())
}

fn assert_log_marker(
    initialized: &InitializedInstance,
    policy: &IngestPolicy,
) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let basis = catalog.pin()?;
    let scope = basis
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope missing after authenticated export")?;
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(
        &initialized._authority,
        &catalog,
        SegmentScope::new(initialized.tenant, SignalKind::Logs, scope.shard_id()),
        protection,
    )?;
    let result = LogStore::new().scan(
        initialized.resource_governor(),
        initialized.tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let record = result
        .records()
        .first()
        .ok_or("authenticated export did not persist a log")?;
    let body = record.body().ok_or("redaction marker body missing")?;
    assert_eq!(body.marker_action(), Some(MarkerAction::Redacted));
    assert_eq!(
        body.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert_eq!(body.as_str(), None);
    assert_eq!(
        find_attribute(record, "secret")?
            .occurrence(0)
            .and_then(|value| value.as_str()),
        Some("source-secret")
    );
    assert!(
        find_attribute(record, "null")?
            .occurrence(0)
            .is_some_and(|value| value.is_null())
    );
    assert_eq!(
        find_attribute(record, "lookalike")?
            .occurrence(0)
            .and_then(|value| value.as_str()),
        Some("[REDACTED]")
    );
    assert_eq!(record.policy_provenance().generation(), policy.generation());
    assert_eq!(record.policy_provenance().digest(), policy.digest());
    assert_eq!(record.policy_provenance().applied_rules(), &["redact-body"]);
    Ok(())
}

fn assert_log_attribute_marker(
    initialized: &InitializedInstance,
    policy: &IngestPolicy,
) -> Result<(), Box<dyn Error>> {
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let basis = catalog.pin()?;
    let scope = basis
        .reachable_ledger_scopes(initialized.tenant, SignalKind::Logs)?
        .into_iter()
        .next()
        .ok_or("log scope missing after authenticated export")?;
    let protection = initialized.key.segment_key(initialized.instance, scope)?;
    let ledger = ActiveSegmentLedger::open(
        &initialized._authority,
        &catalog,
        SegmentScope::new(initialized.tenant, SignalKind::Logs, scope.shard_id()),
        protection,
    )?;
    let result = LogStore::new().scan(
        initialized.resource_governor(),
        initialized.tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let record = result
        .records()
        .first()
        .ok_or("authenticated export did not persist a log")?;
    let value = find_attribute(record, "secret")?
        .occurrence(0)
        .ok_or("marker missing")?;
    assert_eq!(value.marker_action(), Some(MarkerAction::Redacted));
    assert_eq!(
        value.marker_original_kind(),
        Some(AttributeValueKind::String)
    );
    assert_eq!(value.as_str(), None);
    assert!(
        find_attribute(record, "null")?
            .occurrence(0)
            .is_some_and(|value| value.is_null())
    );
    assert_eq!(
        find_attribute(record, "lookalike")?
            .occurrence(0)
            .and_then(|value| value.as_str()),
        Some("[REDACTED]")
    );
    assert_eq!(record.policy_provenance().generation(), policy.generation());
    assert_eq!(record.policy_provenance().digest(), policy.digest());
    assert_eq!(
        record.policy_provenance().applied_rules(),
        &["redact-secret"]
    );
    Ok(())
}

fn find_attribute<'record>(
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

fn attribute(key: &str, value: AnyValue) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(value),
        ..KeyValue::default()
    }
}

fn string_value(value: &str) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::StringValue(value.to_owned())),
    }
}

struct TestRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    fn new() -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent = PathBuf::from("/tmp")
            .join(format!("p-http-log-markers-{}-{nonce}", std::process::id()));
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&secrets)?;
        set_owner_only(&secrets)?;
        Ok(Self {
            parent,
            data,
            secrets,
        })
    }

    fn paths(&self) -> Result<BootstrapPaths, crate::BootstrapFailure> {
        BootstrapPaths::new(
            &self.data,
            &self.secrets,
            positron_kernel::MountQualification::LocalHost,
        )
    }
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}
