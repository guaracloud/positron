//! Forced-shutdown contract.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

use positron_runtime::{
    ApplicationRuntime, BoundEndpoint, BoundListener, HostInputs, InitializationMode,
    ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole, RegisteredTask, RunningTask,
    ServeConfiguration, ShutdownTrigger, TaskCancellation, TaskFailure, TaskJoinOutcome,
    TaskRegistrar, TaskRole,
};

#[path = "support/process_roots.rs"]
mod process_roots;
use process_roots::TestRoots;

struct Host;

impl ListenerFactory for Host {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let endpoint = if request.role() == ListenerRole::Control {
            BoundEndpoint::control(PathBuf::from("/tmp/positron-forced.sock"))?
        } else {
            BoundEndpoint::tcp(
                request.role(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_499)),
            )?
        };
        Ok(Box::new(Listener(endpoint)))
    }
}

struct Listener(BoundEndpoint);

impl BoundListener for Listener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.0
    }
}

impl TaskRegistrar for Host {
    fn register(&self, _role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
        Ok(Box::new(Task))
    }
}

struct Task;

impl RegisteredTask for Task {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        _health: positron_runtime::HealthState,
        _services: positron_runtime::ServiceHandle,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        Ok(Box::new(TaskHandle(cancellation)))
    }
}

struct TaskHandle(TaskCancellation);

impl RunningTask for TaskHandle {
    fn join(&mut self) -> Result<TaskJoinOutcome, TaskFailure> {
        Ok(TaskJoinOutcome::Joined)
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        assert!(self.0.is_cancelled());
        Ok(())
    }
}

#[test]
fn second_signal_forces_abort_and_releases_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("second-signal")?;
    let host = Host;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&host, &host),
    )?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::SecondSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}
