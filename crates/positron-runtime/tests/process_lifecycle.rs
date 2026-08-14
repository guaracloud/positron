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
    fail_close: Option<ListenerRole>,
    mismatched_role: Option<ListenerRole>,
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
    fail_abort: Option<TaskRole>,
    fail_abort_also: Option<TaskRole>,
    fail_abort_all: bool,
    fail_abort_once: Option<TaskRole>,
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
            if self.mismatched_role == Some(role) {
                BoundEndpoint::tcp(
                    ListenerRole::Api,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_401)),
                )?
            } else {
                BoundEndpoint::control(PathBuf::from("/tmp/positron-test-control.sock"))?
            }
        } else {
            BoundEndpoint::tcp(
                if self.mismatched_role == Some(role) {
                    ListenerRole::Api
                } else {
                    role
                },
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, role.test_port())),
            )?
        };
        Ok(Box::new(ObservedListener {
            endpoint,
            fail_close: self.fail_close == Some(role),
        }))
    }
}

struct ObservedListener {
    endpoint: BoundEndpoint,
    fail_close: bool,
}

impl BoundListener for ObservedListener {
    fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }

    fn close(&mut self) -> Result<(), ListenerFailure> {
        if self.fail_close {
            Err(ListenerFailure::BindUnavailable)
        } else {
            Ok(())
        }
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
            fail_abort: self.fail_abort_all
                || self.fail_abort == Some(role)
                || self.fail_abort_also == Some(role),
            fail_abort_once: self.fail_abort_once == Some(role),
        }))
    }
}

struct ObservedRegisteredTask {
    role: TaskRole,
    events: Rc<RefCell<Vec<TaskEvent>>>,
    fail_spawn: bool,
    fail_join: bool,
    fail_abort: bool,
    fail_abort_once: bool,
}

impl RegisteredTask for ObservedRegisteredTask {
    fn spawn(
        self: Box<Self>,
        cancellation: TaskCancellation,
        health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
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
            fail_abort: self.fail_abort,
            fail_abort_once: self.fail_abort_once,
            abort_attempts: 0,
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
        [
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
        ]
    );
    Ok(())
}

#[test]
fn partial_spawn_with_failed_rollback_reports_internal_cleanup_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("spawn-rollback-fault")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Api),
        fail_abort: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("failed rollback must not report only the later spawn failure");

    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) = failure else {
        panic!("unexpected startup outcome: {failure:?}");
    };
    assert_eq!(cleanup.first_task(), Some(TaskRole::Operations));
    assert_eq!(cleanup.task_failures(), 1);
    assert_eq!(cleanup.listener_failures(), 1);
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true)
    )));
    assert_eq!(
        tasks
            .events
            .borrow()
            .iter()
            .filter(|event| matches!(event, TaskEvent::Aborted(..)))
            .cloned()
            .collect::<Vec<_>>(),
        [
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true),
            TaskEvent::Aborted(TaskRole::Operations, ProcessPhase::Recovering, true),
        ]
    );
    Ok(())
}

#[test]
fn nested_spawn_rollback_merges_data_control_and_listener_cleanup_truth()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("nested-cleanup")?;
    let listeners = ObservingListeners {
        fail_close: Some(ListenerRole::Api),
        ..ObservingListeners::default()
    };
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::OtlpHttp),
        fail_abort: Some(TaskRole::Api),
        fail_abort_also: Some(TaskRole::Control),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("nested cleanup ambiguity must be preserved");
    let positron_runtime::ExitOutcome::InternalCleanupFailure(cleanup) = failure else {
        panic!("unexpected outcome: {failure:?}");
    };
    assert_eq!(cleanup.task_failures(), 2);
    assert_eq!(cleanup.listener_failures(), 1);
    assert_eq!(
        cleanup.primary(),
        positron_runtime::CleanupPrimary::TaskUnavailable(TaskRole::OtlpHttp)
    );
    assert_eq!(
        cleanup.failed_roles().collect::<Vec<_>>(),
        [
            positron_runtime::CleanupRole::Task(TaskRole::Api),
            positron_runtime::CleanupRole::Task(TaskRole::Control),
            positron_runtime::CleanupRole::Listener(ListenerRole::Api),
        ]
    );
    assert!(roots.acquire_volume_again().is_ok());
    Ok(())
}

#[test]
fn fenced_partial_task_spawn_failure_aborts_started_tasks_and_releases_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("fenced-spawn-fault")?;
    std::fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let listeners = ObservingListeners::default();
    let tasks = ObservingTasks {
        fail_spawn: Some(TaskRole::Operations),
        ..ObservingTasks::default()
    };

    let failure = ApplicationRuntime::start(
        ServeConfiguration::new(
            roots.bootstrap_paths()?,
            InitializationMode::InitializeIfEmpty,
        ),
        HostInputs::new(&listeners, &tasks),
    )
    .expect_err("fenced task spawn failure must fail startup");

    assert_eq!(
        failure,
        positron_runtime::ExitOutcome::TaskUnavailable(TaskRole::Operations)
    );
    assert!(roots.acquire_volume_again().is_ok());
    assert!(tasks.events.borrow().iter().any(|event| matches!(
        event,
        TaskEvent::Aborted(TaskRole::Control, ProcessPhase::Recovering, true)
    )));
    Ok(())
}

struct ObservedRunningTask {
    role: TaskRole,
    events: Rc<RefCell<Vec<TaskEvent>>>,
    cancellation: TaskCancellation,
    health: positron_runtime::HealthState,
    fail_join: bool,
    fail_abort: bool,
    fail_abort_once: bool,
    abort_attempts: u8,
}

impl RunningTask for ObservedRunningTask {
    fn poll_join(&mut self) -> Result<Option<TaskJoinOutcome>, TaskFailure> {
        self.join().map(Some)
    }

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
        self.abort_attempts = self.abort_attempts.saturating_add(1);
        self.events.borrow_mut().push(TaskEvent::Aborted(
            self.role,
            self.health.phase(),
            self.cancellation.is_cancelled(),
        ));
        if self.fail_abort || (self.fail_abort_once && self.abort_attempts == 1) {
            Err(TaskFailure::AbortUnavailable)
        } else {
            Ok(())
        }
    }
}

#[path = "process_lifecycle/cleanup_outcomes.rs"]
mod cleanup_outcomes;
#[path = "process_lifecycle/listeners.rs"]
mod listeners;
#[path = "process_lifecycle/outcomes.rs"]
mod outcomes;
use outcomes::TestPort;
