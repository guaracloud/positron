use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
    NativeLogAdmissionGroups, NativeSpanAdmissionGroups,
};
use positron_kernel::MountQualification;
use prost::Message;

use super::super::{ResponseEncoding, RpcStatus, receive_traces};
use crate::native_host::native_http::{RequestHead, Response};
use crate::services::ReceiverTestBackend;
use crate::{
    BootstrapPaths, InitializationPlan, InitializedInstance, InstanceBootstrap, ServiceHandle,
};

#[test]
fn live_http_trace_export_maps_retry_classes_and_releases_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let backend = Arc::new(ScriptedBackend::new([
            Completion::Capacity,
            Completion::Retryable,
            Completion::Permanent,
            Completion::Ambiguous,
            Completion::Committed,
        ]));
        let harness = HttpHarness::start(backend.clone())?;
        let baseline = harness.governor_snapshot()?.outstanding_total();

        let capacity = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(
            capacity.status(),
            429,
            "content_type={}, body={:?}, backend_calls={}",
            capacity.content_type(),
            capacity.body(),
            backend.calls()
        );
        assert_eq!(capacity.retry_after_seconds(), Some(1));
        assert_eq!(decode_status(&capacity, encoding).code, 8);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        let retryable = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(retryable.status(), 503);
        assert_eq!(retryable.retry_after_seconds(), None);
        assert_eq!(decode_status(&retryable, encoding).code, 14);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        let permanent = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(permanent.status(), 400);
        assert_eq!(decode_status(&permanent, encoding).code, 3);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        // The backend records the commit before returning the ambiguous result.
        // Dropping this response models a lost producer response; the retry is
        // still allowed to commit because the contract is at-least-once.
        let ambiguous = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(ambiguous.status(), 503);
        assert!(
            decode_status(&ambiguous, encoding)
                .message
                .contains("retry may duplicate spans")
        );
        drop(ambiguous);
        assert_eq!(backend.committed_records(), 1);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);

        let retry_after_lost_response = harness.request(
            encoding,
            trace_body_for(encoding)?,
            None,
            Some(&harness.bearer),
            None,
            None,
        )?;
        assert_eq!(retry_after_lost_response.status(), 200);
        let response = decode_success(&retry_after_lost_response, encoding)?;
        assert!(response.partial_success.is_none());
        assert_eq!(backend.committed_records(), 2);
        assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    }
    Ok(())
}

#[test]
fn live_http_trace_export_rejects_wire_failures_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([]));
    let harness = HttpHarness::start(backend)?;
    let baseline = harness.governor_snapshot()?.outstanding_total();

    let malformed_protobuf = harness.request(
        ResponseEncoding::Protobuf,
        vec![0x0a],
        None,
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(malformed_protobuf.status(), 400);
    assert_eq!(
        decode_status(&malformed_protobuf, ResponseEncoding::Protobuf).code,
        3
    );

    let malformed_json = harness.request(
        ResponseEncoding::Json,
        br#"{"resourceSpans":["#.to_vec(),
        None,
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(malformed_json.status(), 400);
    assert_eq!(
        decode_status(&malformed_json, ResponseEncoding::Json).code,
        3
    );

    let malformed_gzip = harness.request(
        ResponseEncoding::Json,
        vec![0x1f, 0x8b, 0x00],
        Some("gzip"),
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(malformed_gzip.status(), 400);
    assert_eq!(
        decode_status(&malformed_gzip, ResponseEncoding::Json).code,
        3
    );

    let unsupported_media = harness.request_with_content_type(
        "application/octet-stream",
        Vec::new(),
        None,
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(unsupported_media.status(), 415);
    assert_eq!(
        json_message(&unsupported_media)?,
        "OTLP Traces Content-Type is unsupported"
    );

    let unsupported_encoding = harness.request_with_content_type(
        "application/json",
        Vec::new(),
        Some("br"),
        Some(&harness.bearer),
        None,
        None,
    )?;
    assert_eq!(unsupported_encoding.status(), 415);
    assert_eq!(
        json_message(&unsupported_encoding)?,
        "OTLP Traces Content-Encoding is unsupported"
    );

    let missing_auth = harness.request(
        ResponseEncoding::Protobuf,
        trace_body(),
        None,
        None,
        None,
        None,
    )?;
    assert_eq!(missing_auth.status(), 401);
    assert_eq!(
        decode_status(&missing_auth, ResponseEncoding::Protobuf).code,
        16
    );

    let tenant_conflict = harness.request(
        ResponseEncoding::Protobuf,
        trace_body(),
        None,
        Some(&harness.bearer),
        Some("different-tenant"),
        None,
    )?;
    assert_eq!(tenant_conflict.status(), 401);
    assert_eq!(
        decode_status(&tenant_conflict, ResponseEncoding::Protobuf).code,
        16
    );

    let oversized = harness.request(
        ResponseEncoding::Protobuf,
        vec![0],
        None,
        Some(&harness.bearer),
        None,
        Some(1_048_577),
    )?;
    assert_eq!(oversized.status(), 413);
    assert_eq!(
        decode_status(&oversized, ResponseEncoding::Protobuf).code,
        8
    );

    let complete_body = trace_body();
    let truncated = harness.request(
        ResponseEncoding::Protobuf,
        complete_body.clone(),
        None,
        Some(&harness.bearer),
        None,
        Some(complete_body.len().saturating_add(1)),
    )?;
    assert_eq!(truncated.status(), 400);
    assert_eq!(
        decode_status(&truncated, ResponseEncoding::Protobuf).code,
        3
    );
    assert_eq!(harness.governor_snapshot()?.outstanding_total(), baseline);
    assert_eq!(harness.backend_calls(), 0);
    Ok(())
}

fn trace_body() -> Vec<u8> {
    trace_request().encode_to_vec()
}

fn trace_body_for(encoding: ResponseEncoding) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match encoding {
        ResponseEncoding::Protobuf => Ok(trace_body()),
        ResponseEncoding::Json => Ok(serde_json::to_vec(&trace_request())?),
    }
}

fn trace_request() -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x41; 16],
                    span_id: vec![0x42; 8],
                    name: "http-outcome".to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
}

fn decode_status(response: &Response, encoding: ResponseEncoding) -> RpcStatus {
    match encoding {
        ResponseEncoding::Protobuf => RpcStatus::decode(response.body()).expect("status protobuf"),
        ResponseEncoding::Json => {
            let value: serde_json::Value =
                serde_json::from_slice(response.body()).expect("status JSON");
            RpcStatus {
                code: value["code"].as_i64().expect("status code") as i32,
                message: value["message"]
                    .as_str()
                    .expect("status message")
                    .to_owned(),
            }
        },
    }
}

fn decode_success(
    response: &Response,
    encoding: ResponseEncoding,
) -> Result<ExportTraceServiceResponse, Box<dyn std::error::Error>> {
    match encoding {
        ResponseEncoding::Protobuf => Ok(ExportTraceServiceResponse::decode(response.body())?),
        ResponseEncoding::Json => {
            let value: serde_json::Value = serde_json::from_slice(response.body())?;
            Ok(ExportTraceServiceResponse {
                partial_success: value.get("partialSuccess").map(|partial| {
                    opentelemetry_proto::tonic::collector::trace::v1::ExportTracePartialSuccess {
                        rejected_spans: partial["rejectedSpans"]
                            .as_str()
                            .and_then(|value| value.parse().ok())
                            .unwrap_or_default(),
                        error_message: partial["errorMessage"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    }
                }),
            })
        },
    }
}

fn json_message(response: &Response) -> Result<String, Box<dyn std::error::Error>> {
    Ok(
        serde_json::from_slice::<serde_json::Value>(response.body())?["message"]
            .as_str()
            .ok_or("missing JSON message")?
            .to_owned(),
    )
}

#[derive(Clone, Copy)]
enum Completion {
    Capacity,
    Retryable,
    Permanent,
    Ambiguous,
    Committed,
}

struct ScriptedBackend {
    completions: Mutex<VecDeque<Completion>>,
    committed: AtomicUsize,
    calls: AtomicUsize,
}

impl ScriptedBackend {
    fn new(completions: impl IntoIterator<Item = Completion>) -> Self {
        Self {
            completions: Mutex::new(completions.into_iter().collect()),
            committed: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        }
    }

    fn committed_records(&self) -> usize {
        self.committed.load(Ordering::Acquire)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl ReceiverTestBackend for ScriptedBackend {
    fn ingest(&self, _groups: NativeLogAdmissionGroups<'_>) -> IngestRequestOutcome {
        IngestRequestOutcome::new(Vec::new())
    }

    fn handles_traces(&self) -> bool {
        true
    }

    fn ingest_traces(&self, groups: NativeSpanAdmissionGroups<'_>) -> IngestRequestOutcome {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let groups = groups
            .map(|group| (group.shard(), group.records()))
            .collect::<Vec<_>>();
        let completion = self
            .completions
            .lock()
            .expect("script lock")
            .pop_front()
            .expect("scripted completion");
        if matches!(completion, Completion::Ambiguous | Completion::Committed) {
            self.committed.fetch_add(
                groups.iter().map(|(_, records)| records).sum(),
                Ordering::AcqRel,
            );
        }
        let outcome = match completion {
            Completion::Capacity => {
                IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
            },
            Completion::Retryable => {
                IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable)
            },
            Completion::Permanent => IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
            Completion::Ambiguous => {
                IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
            },
            Completion::Committed => return IngestRequestOutcome::new(Vec::new()),
        };
        IngestRequestOutcome::new(
            groups
                .into_iter()
                .map(|(shard, records)| AdmissionGroupOutcome::new(shard, records, outcome))
                .collect(),
        )
    }
}

struct HttpHarness {
    services: ServiceHandle,
    initialized: Arc<InitializedInstance>,
    bearer: String,
    backend: Arc<ScriptedBackend>,
    _roots: TestRoots,
}

impl HttpHarness {
    fn start(backend: Arc<ScriptedBackend>) -> Result<Self, Box<dyn std::error::Error>> {
        let roots = TestRoots::new()?;
        let paths = roots.paths()?;
        drop(InstanceBootstrap::initialize(
            &paths,
            InitializationPlan::non_interactive(),
        )?);
        let bearer = InstanceBootstrap::claim(&paths)?
            .ingest_secret()
            .ok_or("ingest secret missing")?
            .to_owned();
        let initialized = Arc::new(InstanceBootstrap::reopen(&paths)?);
        let services = ServiceHandle::new(Arc::clone(&initialized))?;
        services.install_receiver_test_backend(backend.clone())?;
        Ok(Self {
            services,
            initialized,
            bearer,
            backend,
            _roots: roots,
        })
    }

    fn governor_snapshot(
        &self,
    ) -> Result<positron_kernel::ResourceSnapshot, Box<dyn std::error::Error>> {
        Ok(self.initialized.resource_governor().inspect()?)
    }

    fn backend_calls(&self) -> usize {
        self.backend.calls()
    }

    fn request(
        &self,
        encoding: ResponseEncoding,
        body: Vec<u8>,
        content_encoding: Option<&str>,
        bearer: Option<&str>,
        tenant_hint: Option<&str>,
        declared_length: Option<usize>,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        self.request_with_content_type(
            encoding.content_type(),
            body,
            content_encoding,
            bearer,
            tenant_hint,
            declared_length,
        )
    }

    fn request_with_content_type(
        &self,
        content_type: &str,
        body: Vec<u8>,
        content_encoding: Option<&str>,
        bearer: Option<&str>,
        tenant_hint: Option<&str>,
        declared_length: Option<usize>,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = listener.local_addr()?;
        let mut client = TcpStream::connect(endpoint)?;
        let (mut server, _) = listener.accept()?;
        client.write_all(&body)?;
        client.shutdown(Shutdown::Write)?;
        let result = receive_traces(
            &mut server,
            RequestHead {
                method: "POST".to_owned(),
                path: "/v1/traces".to_owned(),
                content_length: declared_length.unwrap_or(body.len()),
                bearer: bearer.map(str::to_owned),
                content_type: Some(content_type.to_owned()),
                content_encoding: content_encoding.map(str::to_owned),
                tenant_hint: tenant_hint.map(str::to_owned),
            },
            &self.services,
        );
        Ok(match result {
            Ok(response) | Err(response) => response,
        })
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
        let parent = PathBuf::from("/tmp").join(format!(
            "p-http-trace-outcomes-{}-{nonce}",
            std::process::id()
        ));
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
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
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
