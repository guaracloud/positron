use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, ExitOutcome, HostInputs, InitializationMode,
    InstanceBootstrap, NativeBindings, RunningProcess, ServeConfiguration, ShutdownTrigger,
};
use tonic::Request;

pub(super) type TestError = Box<dyn std::error::Error>;

pub(super) struct LiveGrpcHarness {
    process: Option<RunningProcess>,
    endpoint: SocketAddr,
    bearer: String,
    query_secret: String,
    _roots: TestRoots,
}

pub(super) struct ForcedGrpcHarness {
    roots: TestRoots,
    endpoint: SocketAddr,
    bearer: String,
    trigger: mpsc::SyncSender<ShutdownTrigger>,
    outcome: mpsc::Receiver<ExitOutcome>,
    server: Option<JoinHandle<()>>,
}

impl ForcedGrpcHarness {
    pub(super) fn start(label: &str) -> Result<Self, TestError> {
        let roots = TestRoots::new(label)?;
        let paths = roots.paths()?;
        drop(InstanceBootstrap::initialize(
            &paths,
            positron_runtime::InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let bearer = claim
            .ingest_secret()
            .ok_or("ingest secret missing")?
            .to_owned();
        let host = positron_runtime::NativeHost::new(bindings(&roots, "forced")?);
        let (endpoint_sender, endpoint_receiver) = mpsc::sync_channel(1);
        let (trigger_sender, trigger_receiver) = mpsc::sync_channel(1);
        let (outcome_sender, outcome_receiver) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || {
            let Ok(process) = ApplicationRuntime::start(
                ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
                HostInputs::new(&host, &host),
            ) else {
                return;
            };
            let Ok(endpoint) = address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::OtlpGrpc,
            ) else {
                return;
            };
            if endpoint_sender.send(endpoint).is_err() {
                return;
            }
            let Ok(trigger) = trigger_receiver.recv() else {
                return;
            };
            let _ = outcome_sender.send(process.shutdown(trigger));
        });
        let endpoint = endpoint_receiver.recv_timeout(std::time::Duration::from_secs(2))?;
        Ok(Self {
            roots,
            endpoint,
            bearer,
            trigger: trigger_sender,
            outcome: outcome_receiver,
            server: Some(server),
        })
    }

    pub(super) const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub(super) fn bearer(&self) -> &str {
        &self.bearer
    }

    pub(super) fn trigger(&self, trigger: ShutdownTrigger) -> Result<(), TestError> {
        Ok(self.trigger.send(trigger)?)
    }

    pub(super) fn outcome_within(
        &self,
        duration: std::time::Duration,
    ) -> Result<ExitOutcome, mpsc::RecvTimeoutError> {
        self.outcome.recv_timeout(duration)
    }

    pub(super) fn finish(mut self) -> Result<bool, TestError> {
        self.server
            .take()
            .ok_or("server thread missing")?
            .join()
            .map_err(|_| "server thread panicked")?;
        Ok(self.roots.acquire_volume_again().is_ok())
    }
}

impl LiveGrpcHarness {
    pub(super) fn start(label: &str) -> Result<Self, TestError> {
        Self::start_with(label, std::convert::identity)
    }

    pub(super) fn start_with(
        label: &str,
        configure: impl FnOnce(ServeConfiguration) -> ServeConfiguration,
    ) -> Result<Self, TestError> {
        let roots = TestRoots::new(label)?;
        let paths = roots.paths()?;
        drop(InstanceBootstrap::initialize(
            &paths,
            positron_runtime::InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let bearer = claim
            .ingest_secret()
            .ok_or("ingest secret missing")?
            .to_owned();
        let query_secret = claim
            .query_secret()
            .ok_or("query secret missing")?
            .to_owned();
        let host = positron_runtime::NativeHost::new(bindings(&roots, label)?);
        let configuration = configure(ServeConfiguration::new(
            paths,
            InitializationMode::ExistingOnly,
        ));
        let process = ApplicationRuntime::start(configuration, HostInputs::new(&host, &host))?;
        let endpoint = address(
            &process.bound_endpoints(),
            positron_runtime::ListenerRole::OtlpGrpc,
        )?;
        Ok(Self {
            process: Some(process),
            endpoint,
            bearer,
            query_secret,
            _roots: roots,
        })
    }

    pub(super) const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub(super) fn bearer(&self) -> &str {
        &self.bearer
    }

    pub(super) fn authorize<T>(&self, mut request: Request<T>) -> Result<Request<T>, TestError> {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {}", self.bearer).parse()?);
        Ok(request)
    }

    pub(super) fn query_log_bodies(&self, query: &str) -> Result<Vec<String>, TestError> {
        let services = self
            .process
            .as_ref()
            .and_then(RunningProcess::services)
            .ok_or("runtime services missing")?;
        Ok(services.query_log_bodies(
            &self.query_secret,
            query,
            positron_query::QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                .with_cpu_work_units(15)?,
        )?)
    }

    pub(super) async fn shutdown(
        mut self,
        trigger: ShutdownTrigger,
    ) -> Result<ExitOutcome, TestError> {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let process = self.process.take().ok_or("runtime process missing")?;
        Ok(process.shutdown(trigger))
    }

    pub(super) fn crash(&mut self) -> Result<(), TestError> {
        drop(self.process.take().ok_or("runtime process missing")?);
        Ok(())
    }

    pub(super) fn restart(&mut self) -> Result<(), TestError> {
        if self.process.is_some() {
            return Err("runtime process is already running".into());
        }
        let paths = self._roots.paths()?;
        let host = positron_runtime::NativeHost::new(bindings(&self._roots, "restart")?);
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
            HostInputs::new(&host, &host),
        )?;
        self.endpoint = address(
            &process.bound_endpoints(),
            positron_runtime::ListenerRole::OtlpGrpc,
        )?;
        self.process = Some(process);
        Ok(())
    }
}

pub(super) fn bindings(
    roots: &TestRoots,
    _label: &str,
) -> Result<NativeBindings, Box<dyn std::error::Error>> {
    let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let control = roots.parent.join("control.sock");
    Ok(NativeBindings::new(
        control, ephemeral, ephemeral, ephemeral, ephemeral, ephemeral,
    )?)
}

pub(super) fn address(
    endpoints: &[positron_runtime::BoundEndpoint],
    role: positron_runtime::ListenerRole,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.role() == role)
        .and_then(positron_runtime::BoundEndpoint::socket_address)
        .ok_or_else(|| format!("{role:?} endpoint missing").into())
}

pub(super) fn otlp_request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    observed_time_unix_nano: 84,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

pub(super) struct TestRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    pub(super) fn new(label: &str) -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent =
            PathBuf::from("/tmp").join(format!("p-grpc-{label}-{}-{nonce}", std::process::id()));
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

    pub(super) fn paths(&self) -> Result<BootstrapPaths, positron_runtime::BootstrapFailure> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
    }

    pub(super) fn acquire_volume_again(
        &self,
    ) -> Result<positron_kernel::OwnedPrimaryDataVolume, positron_kernel::VolumeFailure> {
        positron_kernel::PrimaryDataVolume::acquire(&self.data, MountQualification::LocalHost)
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.parent) {
            eprintln!("temporary test root cleanup failed: {error}");
        }
    }
}
