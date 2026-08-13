//! Public process-lifecycle contract tests for the runnable M1 database.

use positron_runtime::{
    ApplicationRuntime, BoundEndpoint, BoundListener, HostInputs, InitializationMode,
    ListenerFactory, ListenerFailure, ListenerRequest, ListenerRole, ProcessPhase, Readiness,
    RegisteredTask, RunningTask, ServeConfiguration, ShutdownTrigger, TaskCancellation,
    TaskFailure, TaskJoinOutcome, TaskRegistrar, TaskRole,
};
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::rc::Rc;

#[path = "support/process_roots.rs"]
pub mod process_roots;
pub use process_roots::TestRoots;

#[derive(Default)]
pub struct ObservingListeners {
    pub bound: RefCell<Vec<ListenerRole>>,
    pub health: RefCell<Vec<positron_runtime::HealthState>>,
    fail_role: Option<ListenerRole>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TaskEvent {
    Registered(TaskRole),
    Spawned(TaskRole),
    Joined(TaskRole, ProcessPhase, bool),
    Aborted(TaskRole, ProcessPhase, bool),
}

#[derive(Default)]
pub struct ObservingTasks {
    events: Rc<RefCell<Vec<TaskEvent>>>,
    fail_registration: Option<TaskRole>,
    fail_spawn: Option<TaskRole>,
    fail_join: Option<TaskRole>,
}

impl ObservingTasks {
    pub fn failing_registration(role: TaskRole) -> Self {
        Self {
            fail_registration: Some(role),
            ..Self::default()
        }
    }

    pub fn no_task_spawned(&self) -> bool {
        !self
            .events
            .borrow()
            .iter()
            .any(|event| matches!(event, TaskEvent::Spawned(_)))
    }
}

impl ListenerFactory for ObservingListeners {
    fn bind(&self, request: ListenerRequest) -> Result<Box<dyn BoundListener>, ListenerFailure> {
        let role = request.role();
        self.bound.borrow_mut().push(role);
        self.health.borrow_mut().push(request.health());
        if self.fail_role == Some(role) {
            return Err(ListenerFailure::BindUnavailable);
        }
        let endpoint = if role == ListenerRole::Control {
            BoundEndpoint::control(PathBuf::from("/tmp/positron-test-control.sock"))?
        } else {
            BoundEndpoint::tcp(
                role,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, role.test_port())),
            )?
        };
        Ok(Box::new(ObservedListener { endpoint }))
    }
}

#[test]
fn listener_bind_failure_is_typed_and_releases_the_volume_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("bind-fault")?;
    let listeners = ObservingListeners {
        fail_role: Some(ListenerRole::OtlpHttp),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks::default();

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("listener bind failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::ListenerUnavailable(ListenerRole::OtlpHttp)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert!(
        !tasks
            .events
            .borrow()
            .iter()
            .any(|event| matches!(event, TaskEvent::Spawned(_)))
    );
    Ok(())
}

struct ObservedListener {
    endpoint: BoundEndpoint,
}

impl BoundListener for ObservedListener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }
}

impl TaskRegistrar for ObservingTasks {
    fn register(&self, role: TaskRole) -> Result<Box<dyn RegisteredTask>, TaskFailure> {
        self.events.borrow_mut().push(TaskEvent::Registered(role));
        if self.fail_registration == Some(role) {
            return Err(TaskFailure::RegistrationUnavailable);
        }
        Ok(Box::new(ObservedRegisteredTask {
            role,
            events: Rc::clone(&self.events),
            fail_spawn: self.fail_spawn == Some(role),
            fail_join: self.fail_join == Some(role),
        }))
    }
}

struct ObservedRegisteredTask {
    role: TaskRole,
    events: Rc<RefCell<Vec<TaskEvent>>>,
    fail_spawn: bool,
    fail_join: bool,
}

impl RegisteredTask for ObservedRegisteredTask {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        health: positron_runtime::HealthState,
        _services: positron_runtime::ServiceHandle,
    ) -> Result<Box<dyn RunningTask>, TaskFailure> {
        self.events.borrow_mut().push(TaskEvent::Spawned(self.role));
        if self.fail_spawn {
            return Err(TaskFailure::SpawnUnavailable);
        }
        Ok(Box::new(ObservedRunningTask {
            role: self.role,
            events: Rc::clone(&self.events),
            cancellation,
            health,
            fail_join: self.fail_join,
        }))
    }
}

#[test]
fn partial_task_spawn_failure_aborts_started_tasks_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("spawn-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("task spawn failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Api)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [TaskEvent::Aborted(
            TaskRole::Operations,
            ProcessPhase::Recovering,
            true,
        )]
    );
    Ok(())
}

struct ObservedRunningTask {
    role: TaskRole,
    events: Rc<RefCell<Vec<TaskEvent>>>,
    cancellation: TaskCancellation,
    health: positron_runtime::HealthState,
    fail_join: bool,
}

impl RunningTask for ObservedRunningTask {
    fn join(&mut self) -> Result<TaskJoinOutcome, TaskFailure> {
        self.events.borrow_mut().push(TaskEvent::Joined(
            self.role,
            self.health.phase(),
            self.cancellation.is_cancelled(),
        ));
        if self.fail_join {
            Err(TaskFailure::JoinUnavailable)
        } else {
            Ok(TaskJoinOutcome::Joined)
        }
    }

    fn abort(&mut self) -> Result<(), TaskFailure> {
        self.events.borrow_mut().push(TaskEvent::Aborted(
            self.role,
            self.health.phase(),
            self.cancellation.is_cancelled(),
        ));
        Ok(())
    }
}

#[test]
fn deadline_aborts_every_task_and_never_reports_graceful_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("deadline")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();

    let outcome = process.shutdown(ShutdownTrigger::DeadlineExpired);

    assert_eq!(outcome, positron_runtime::ExitOutcome::Forced);
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert!(roots.acquire_volume_again().is_ok());
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Stopping, true),
            TaskEvent::Aborted(TaskRole::Api, ProcessPhase::Stopping, true),
            TaskEvent::Aborted(TaskRole::OtlpHttp, ProcessPhase::Stopping, true),
        ]
    );
    Ok(())
}

#[test]
fn task_join_failure_reconciles_with_abort_and_forced_exit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("join-fault")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_join: Some(TaskRole::Api),
        ..ObservingTasks::default()
    };
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    let health = process.health();

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Forced
    );
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Api, ProcessPhase::Stopping, true)
    )));
    Ok(())
}

#[test]
fn missing_instance_is_a_typed_dependency_outage_without_data_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("missing")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(roots.bootstrap_paths()?, InitializationMode::ExistingOnly),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("missing instance must fail closed");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::StartupUnavailable(
            positron_runtime::BootstrapFailureCode::InconsistentRoots
        )
    );
    assert_eq!(listeners.bound.borrow().as_slice(), control_plane());
    Ok(())
}

#[test]
fn ambiguous_bootstrap_fences_without_exposing_a_data_endpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("fenced")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )?;
    assert_eq!(process.health().phase(), ProcessPhase::Fenced);
    assert_eq!(process.health().readiness(), Readiness::NotReady);
    assert_eq!(listeners.bound.borrow().as_slice(), control_plane());
    Ok(())
}

#[test]
fn first_signal_closes_admission_joins_registered_tasks_and_releases_ownership_last()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("graceful")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks::default();
    let configuration = ServeConfiguration::new(
        roots.bootstrap_paths()?,
        InitializationMode::InitializeIfEmpty,
    );
    let process = ApplicationRuntime::start(configuration, HostInputs::new(&listeners, &tasks))?;
    let health = process.health();
    assert!(format!("{process:?}").contains("RunningProcess"));

    let outcome = process.shutdown(ShutdownTrigger::FirstSignal);

    assert_eq!(outcome, positron_runtime::ExitOutcome::Graceful);
    assert_eq!(health.phase(), ProcessPhase::Stopped);
    assert_eq!(health.readiness(), Readiness::NotReady);
    assert!(roots.acquire_volume_again().is_ok());
    let events = tasks.events.borrow();
    assert_eq!(events.len(), 9);
    assert!(matches!(
        events.last(),
        Some(TaskEvent::Joined(TaskRole::OtlpHttp, ..))
    ));
    Ok(())
}

trait TestPort {
    fn test_port(self) -> u16;
}

const fn control_plane() -> &'static [ListenerRole] {
    &[ListenerRole::Control, ListenerRole::Operations]
}

impl TestPort for ListenerRole {
    fn test_port(self) -> u16 {
        match self {
            ListenerRole::Control => 42_399,
            ListenerRole::Operations => 42_400,
            ListenerRole::Api => 42_401,
            ListenerRole::OtlpGrpc => 42_402,
            ListenerRole::OtlpHttp => 42_403,
        }
    }
}
