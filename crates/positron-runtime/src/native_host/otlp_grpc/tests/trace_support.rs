use std::collections::VecDeque;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
    NativeLogAdmissionGroups, NativeSpanAdmissionGroups,
};
use positron_kernel::MountQualification;
use prost::Message;

use super::super::serve;
use crate::native_host::{Admission, NativeListener};
use crate::services::ReceiverTestBackend;
use crate::{
    BootstrapPaths, InitializationPlan, InitializedInstance, InstanceBootstrap, ListenerRole,
    ServiceHandle, TaskCancellation,
};

static TRACE_WIRE_TEST: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(super) enum Completion {
    Capacity,
    Retryable,
    Permanent,
    Ambiguous,
    Committed,
    Stall,
}

pub(super) struct ScriptedBackend {
    completions: Mutex<VecDeque<Completion>>,
    committed: AtomicUsize,
    calls: AtomicUsize,
    stall_entered: AtomicBool,
    stall_release: AtomicBool,
}

impl ScriptedBackend {
    pub(super) fn new(completions: impl IntoIterator<Item = Completion>) -> Self {
        Self {
            completions: Mutex::new(completions.into_iter().collect()),
            committed: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            stall_entered: AtomicBool::new(false),
            stall_release: AtomicBool::new(false),
        }
    }

    pub(super) fn committed_records(&self) -> usize {
        self.committed.load(Ordering::Acquire)
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }

    pub(super) fn stall_entered(&self) -> bool {
        self.stall_entered.load(Ordering::Acquire)
    }

    pub(super) fn release_stall(&self) {
        self.stall_release.store(true, Ordering::Release);
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
        if matches!(completion, Completion::Stall) {
            self.stall_entered.store(true, Ordering::Release);
            while !self.stall_release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            return IngestRequestOutcome::new(Vec::new());
        }
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
            Completion::Committed | Completion::Stall => {
                return IngestRequestOutcome::new(Vec::new());
            },
        };
        IngestRequestOutcome::new(
            groups
                .into_iter()
                .map(|(shard, records)| AdmissionGroupOutcome::new(shard, records, outcome))
                .collect(),
        )
    }
}

pub(super) struct ReceiverHarness {
    pub(super) endpoint: SocketAddr,
    pub(super) bearer: String,
    pub(super) initialized: Arc<InitializedInstance>,
    pub(super) backend: Arc<ScriptedBackend>,
    cancellation: TaskCancellation,
    force: TaskCancellation,
    server: Option<JoinHandle<()>>,
    _test_guard: MutexGuard<'static, ()>,
    _roots: TestRoots,
}

impl ReceiverHarness {
    pub(super) fn start(backend: Arc<ScriptedBackend>) -> Result<Self, Box<dyn std::error::Error>> {
        let test_guard = match TRACE_WIRE_TEST.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
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
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        let admission = Arc::new(Admission {
            role: ListenerRole::OtlpGrpc,
            listener: NativeListener::Tcp(listener),
            accepting: AtomicBool::new(true),
            control_path: None,
        });
        let cancellation = TaskCancellation::new();
        let serve_cancellation = cancellation.clone();
        let force = TaskCancellation::new();
        let serve_force = force.clone();
        let server = std::thread::spawn(move || {
            serve(admission, serve_cancellation, serve_force, Some(services))
                .expect("test OTLP gRPC server");
        });
        Ok(Self {
            endpoint,
            bearer,
            initialized,
            backend,
            cancellation,
            force,
            server: Some(server),
            _test_guard: test_guard,
            _roots: roots,
        })
    }

    pub(super) fn authorize_trace(
        &self,
        mut request: tonic::Request<ExportTraceServiceRequest>,
    ) -> Result<tonic::Request<ExportTraceServiceRequest>, Box<dyn std::error::Error>> {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {}", self.bearer).parse()?);
        Ok(request)
    }

    pub(super) fn authorize_trace_with_tenant(
        &self,
        request: tonic::Request<ExportTraceServiceRequest>,
        tenant: &str,
    ) -> Result<tonic::Request<ExportTraceServiceRequest>, Box<dyn std::error::Error>> {
        let mut request = self.authorize_trace(request)?;
        request
            .metadata()
            .get("authorization")
            .ok_or("authorization metadata missing")?;
        request
            .metadata_mut()
            .insert("x-scope-orgid", tenant.parse()?);
        Ok(request)
    }

    pub(super) fn snapshot(
        &self,
    ) -> Result<positron_kernel::ResourceSnapshot, Box<dyn std::error::Error>> {
        Ok(self.initialized.resource_governor().inspect()?)
    }

    pub(super) fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.backend.release_stall();
        self.cancellation.cancel();
        self.force.cancel();
        if let Some(server) = self.server.take() {
            server.join().map_err(|_| "server panicked")?;
        }
        Ok(())
    }
}

impl Drop for ReceiverHarness {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(super) fn trace_request(seed: u8) -> tonic::Request<ExportTraceServiceRequest> {
    tonic::Request::new(ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![seed; 16],
                    span_id: vec![seed.wrapping_add(1); 8],
                    name: "grpc-trace".to_owned(),
                    start_time_unix_nano: 42,
                    end_time_unix_nano: 84,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    })
}

pub(super) fn trace_frame(seed: u8) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body = trace_request(seed).into_inner().encode_to_vec();
    let length = u32::try_from(body.len())?;
    let mut frame = Vec::with_capacity(body.len().saturating_add(5));
    frame.push(0);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
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
        let parent =
            PathBuf::from("/tmp").join(format!("p-grpc-trace-wire-{}-{nonce}", std::process::id()));
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
