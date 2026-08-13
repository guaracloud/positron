use std::sync::{Arc, Mutex};

use crate::health::ProcessState;
use crate::{
    BootstrapFailureCode, BootstrapPaths, BoundEndpoint, BoundListener, HealthState,
    InitializationPlan, InstanceBootstrap, ListenerFactory, ListenerRequest, ListenerRole,
    ProcessPhase, RegisteredTask, RunningTask, ServiceHandle, TaskCancellation, TaskJoinOutcome,
    TaskRegistrar, TaskRole,
};

/// Whether serving may initialize a provably empty instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationMode {
    ExistingOnly,
    InitializeIfEmpty,
}

/// Fully typed inputs needed to establish the M1 database authorities.
#[derive(Debug)]
pub struct ServeConfiguration {
    paths: BootstrapPaths,
    initialization: InitializationMode,
}

impl ServeConfiguration {
    #[must_use]
    pub const fn new(paths: BootstrapPaths, initialization: InitializationMode) -> Self {
        Self {
            paths,
            initialization,
        }
    }
}

/// Injected host boundaries; database modules remain concrete.
pub struct HostInputs<'host> {
    listeners: &'host dyn ListenerFactory,
    tasks: &'host dyn TaskRegistrar,
}

impl<'host> HostInputs<'host> {
    #[must_use]
    pub const fn new(
        listeners: &'host dyn ListenerFactory,
        tasks: &'host dyn TaskRegistrar,
    ) -> Self {
        Self { listeners, tasks }
    }
}

/// The one stable process outcome mapped by native and managed launchers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitOutcome {
    Graceful,
    Forced,
    InvalidConfiguration,
    StartupUnavailable(BootstrapFailureCode),
    ListenerUnavailable(ListenerRole),
    TaskUnavailable(TaskRole),
    Fenced,
}

impl std::fmt::Display for ExitOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Positron process exited")
    }
}

impl std::error::Error for ExitOutcome {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownTrigger {
    FirstSignal,
    SecondSignal,
    DeadlineExpired,
}

/// Owns all listeners, kernel authority, key custody, and process phase.
pub struct RunningProcess {
    state: ProcessState,
    listeners: Vec<Box<dyn BoundListener>>,
    tasks: Vec<Box<dyn RunningTask>>,
    cancellation: TaskCancellation,
    instance: Option<Arc<Mutex<crate::InitializedInstance>>>,
    services: Option<ServiceHandle>,
}

impl std::fmt::Debug for RunningProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningProcess")
            .field("phase", &self.state.health().phase())
            .field("listener_count", &self.listeners.len())
            .field("task_count", &self.tasks.len())
            .finish_non_exhaustive()
    }
}

impl RunningProcess {
    #[must_use]
    pub fn health(&self) -> HealthState {
        self.state.health()
    }

    #[must_use]
    pub fn bound_endpoints(&self) -> Vec<BoundEndpoint> {
        self.listeners
            .iter()
            .map(|listener| listener.endpoint().clone())
            .collect()
    }

    #[must_use]
    pub fn services(&self) -> Option<ServiceHandle> {
        self.services.clone()
    }

    #[must_use]
    pub fn shutdown(mut self, trigger: ShutdownTrigger) -> ExitOutcome {
        if trigger != ShutdownTrigger::FirstSignal {
            return self.abort_shutdown();
        }
        self.state.transition(ProcessPhase::Draining);
        self.listeners
            .retain(|listener| !listener.endpoint().role().is_data());
        if self.instance.as_ref().is_some_and(|instance| {
            instance
                .lock()
                .map_or(true, |instance| instance.begin_shutdown().is_err())
        }) {
            return self.abort_shutdown();
        }
        self.cancellation.cancel();
        for task in &mut self.tasks {
            match task.join() {
                Ok(TaskJoinOutcome::Joined) => {},
                Ok(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal) | Err(_) => {
                    return self.abort_shutdown();
                },
            }
        }
        self.state.transition(ProcessPhase::Stopping);
        self.tasks.clear();
        self.listeners.clear();
        self.instance.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
        ExitOutcome::Graceful
    }

    fn abort_shutdown(&mut self) -> ExitOutcome {
        self.state.transition(ProcessPhase::Stopping);
        self.cancellation.cancel();
        for task in &mut self.tasks {
            let _ = task.abort();
        }
        self.tasks.clear();
        self.listeners.clear();
        self.instance.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
        ExitOutcome::Forced
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        self.state.transition(ProcessPhase::Stopping);
        self.listeners.clear();
        for task in &mut self.tasks {
            let _ = task.abort();
        }
        self.tasks.clear();
        self.instance.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
    }
}

/// Sole owner of the runnable database lifecycle.
pub enum ApplicationRuntime {}

impl ApplicationRuntime {
    pub fn start(
        configuration: ServeConfiguration,
        host: HostInputs<'_>,
    ) -> Result<RunningProcess, ExitOutcome> {
        let state = ProcessState::starting();
        let mut listeners = Vec::with_capacity(5);
        bind(
            ListenerRole::Control,
            &state,
            host.listeners,
            &mut listeners,
        )?;
        bind(
            ListenerRole::Operations,
            &state,
            host.listeners,
            &mut listeners,
        )?;
        state.transition(ProcessPhase::Recovering);
        let instance = match configuration.initialization {
            InitializationMode::ExistingOnly => InstanceBootstrap::reopen(&configuration.paths),
            InitializationMode::InitializeIfEmpty => InstanceBootstrap::initialize(
                &configuration.paths,
                InitializationPlan::non_interactive(),
            ),
        };
        let instance = match instance {
            Ok(instance) => instance,
            Err(failure)
                if fences(failure.code())
                    && !(configuration.initialization == InitializationMode::ExistingOnly
                        && failure.code() == BootstrapFailureCode::InconsistentRoots) =>
            {
                state.transition(ProcessPhase::Fenced);
                return Ok(RunningProcess {
                    state,
                    listeners,
                    tasks: Vec::new(),
                    cancellation: TaskCancellation::new(),
                    instance: None,
                    services: None,
                });
            },
            Err(failure) => return Err(ExitOutcome::StartupUnavailable(failure.code())),
        };
        let instance = Arc::new(Mutex::new(instance));
        let services = ServiceHandle::new(Arc::clone(&instance));
        let registered = register_tasks(host.tasks)?;
        for role in [ListenerRole::Api, ListenerRole::OtlpHttp] {
            bind(role, &state, host.listeners, &mut listeners)?;
        }
        let cancellation = TaskCancellation::new();
        let tasks = spawn_tasks(registered, &cancellation, &state, &services)?;
        state.transition(ProcessPhase::Serving);
        Ok(RunningProcess {
            state,
            listeners,
            tasks,
            cancellation,
            instance: Some(instance),
            services: Some(services),
        })
    }
}

type RegisteredTasks = Vec<(TaskRole, Box<dyn RegisteredTask>)>;

fn register_tasks(registrar: &dyn TaskRegistrar) -> Result<RegisteredTasks, ExitOutcome> {
    [TaskRole::Operations, TaskRole::Api, TaskRole::OtlpHttp]
        .into_iter()
        .map(|role| {
            let registered = registrar
                .register(role)
                .map_err(|_| ExitOutcome::TaskUnavailable(role))?;
            Ok((role, registered))
        })
        .collect()
}

fn spawn_tasks(
    registered: Vec<(TaskRole, Box<dyn RegisteredTask>)>,
    cancellation: &TaskCancellation,
    state: &ProcessState,
    services: &ServiceHandle,
) -> Result<Vec<Box<dyn RunningTask>>, ExitOutcome> {
    let mut running = Vec::with_capacity(registered.len());
    for (role, task) in registered {
        match task.spawn(cancellation.clone(), state.health(), services.clone()) {
            Ok(task) => running.push(task),
            Err(_) => {
                cancellation.cancel();
                for task in &mut running {
                    let _ = task.abort();
                }
                return Err(ExitOutcome::TaskUnavailable(role));
            },
        }
    }
    Ok(running)
}

fn bind(
    role: ListenerRole,
    state: &ProcessState,
    factory: &dyn ListenerFactory,
    listeners: &mut Vec<Box<dyn BoundListener>>,
) -> Result<(), ExitOutcome> {
    let listener = factory
        .bind(ListenerRequest::new(role, state.health()))
        .map_err(|_| ExitOutcome::ListenerUnavailable(role))?;
    if listener.endpoint().role() != role {
        return Err(ExitOutcome::ListenerUnavailable(role));
    }
    listeners.push(listener);
    Ok(())
}

const fn fences(code: BootstrapFailureCode) -> bool {
    matches!(
        code,
        BootstrapFailureCode::InconsistentRoots
            | BootstrapFailureCode::CorruptState
            | BootstrapFailureCode::IdentityMismatch
    )
}
