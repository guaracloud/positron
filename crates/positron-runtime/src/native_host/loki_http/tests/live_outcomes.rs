use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
    NativeLogAdmissionGroups,
};
use positron_kernel::MountQualification;

use crate::health::ProcessState;
use crate::native_host::{Admission, NativeListener, serve_http};
use crate::services::ReceiverTestBackend;
use crate::{
    BootstrapPaths, InitializationPlan, InstanceBootstrap, ListenerRole, ServiceHandle,
    TaskCancellation,
};

#[test]
fn live_push_distinguishes_capacity_retry_ambiguity_and_permanent_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(ScriptedBackend::new([
        Completion::Capacity,
        Completion::Storage,
        Completion::Ambiguous,
        Completion::Permanent,
    ]));
    let harness = ReceiverHarness::start(backend.clone())?;

    let capacity = harness.push()?;
    assert!(capacity.starts_with("HTTP/1.1 429 "));
    assert!(capacity.contains("Retry-After: 1\r\n"));
    let storage = harness.push()?;
    assert!(storage.starts_with("HTTP/1.1 503 "));
    let ambiguous = harness.push()?;
    assert!(ambiguous.starts_with("HTTP/1.1 503 "));
    assert!(ambiguous.contains("retry may duplicate records"));
    assert_eq!(backend.committed_records(), 1);
    let permanent = harness.push()?;
    assert!(permanent.starts_with("HTTP/1.1 400 "));
    assert_eq!(backend.committed_records(), 1);
    harness.finish()?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Completion {
    Capacity,
    Storage,
    Ambiguous,
    Permanent,
}

struct ScriptedBackend {
    completions: Mutex<VecDeque<Completion>>,
    committed: AtomicUsize,
}

impl ScriptedBackend {
    fn new(completions: impl IntoIterator<Item = Completion>) -> Self {
        Self {
            completions: Mutex::new(completions.into_iter().collect()),
            committed: AtomicUsize::new(0),
        }
    }

    fn committed_records(&self) -> usize {
        self.committed.load(Ordering::Acquire)
    }
}

impl ReceiverTestBackend for ScriptedBackend {
    fn ingest(&self, groups: NativeLogAdmissionGroups<'_>) -> IngestRequestOutcome {
        let groups = groups
            .map(|group| (group.shard(), group.records()))
            .collect::<Vec<_>>();
        let completion = self
            .completions
            .lock()
            .expect("script lock")
            .pop_front()
            .expect("scripted completion");
        if matches!(completion, Completion::Ambiguous) {
            self.committed.fetch_add(
                groups.iter().map(|(_, records)| records).sum(),
                Ordering::AcqRel,
            );
        }
        let outcome = match completion {
            Completion::Capacity => {
                IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
            },
            Completion::Storage => IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
            Completion::Ambiguous => {
                IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
            },
            Completion::Permanent => IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
        };
        IngestRequestOutcome::new(
            groups
                .into_iter()
                .map(|(shard, records)| AdmissionGroupOutcome::new(shard, records, outcome))
                .collect(),
        )
    }
}

struct ReceiverHarness {
    endpoint: SocketAddr,
    bearer: String,
    cancellation: TaskCancellation,
    server: Option<JoinHandle<()>>,
    _roots: TestRoots,
}

impl ReceiverHarness {
    fn start(backend: Arc<dyn ReceiverTestBackend>) -> Result<Self, Box<dyn std::error::Error>> {
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
        let services = ServiceHandle::new(Arc::new(InstanceBootstrap::reopen(&paths)?))?;
        services.install_receiver_test_backend(backend)?;
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        let admission = Arc::new(Admission {
            role: ListenerRole::LokiPush,
            listener: NativeListener::Tcp(listener),
            accepting: AtomicBool::new(true),
            control_path: None,
        });
        let cancellation = TaskCancellation::new();
        let serve_cancellation = cancellation.clone();
        let health = ProcessState::starting().health();
        let server = std::thread::spawn(move || {
            serve_http(admission, serve_cancellation, health, Some(services));
        });
        Ok(Self {
            endpoint,
            bearer,
            cancellation,
            server: Some(server),
            _roots: roots,
        })
    }

    fn push(&self) -> Result<String, Box<dyn std::error::Error>> {
        let body = br#"{"streams":[{"stream":{"app":"outcomes"},"values":[["42","line"]]}]}"#;
        let mut stream = TcpStream::connect_timeout(&self.endpoint, Duration::from_secs(2))?;
        write!(
            stream,
            "POST /loki/api/v1/push HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            self.bearer,
            body.len()
        )?;
        stream.write_all(body)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.cancellation.cancel();
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
            PathBuf::from("/tmp").join(format!("p-loki-private-{}-{nonce}", std::process::id()));
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
