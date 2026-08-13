use std::sync::{Arc, Mutex};

use positron_kernel::OwnedPrimaryDataVolume;

use crate::health::ProcessState;
use crate::{
    BootstrapFailureCode, BootstrapPaths, BoundEndpoint, BoundListener, HealthState,
    InitializationPlan, InstanceBootstrap, ListenerFactory, ListenerRequest, ListenerRole,
    ProcessPhase, RegisteredTask, RunningTask, ServiceHandle, TaskCancellation, TaskFailure,
    TaskJoinOutcome, TaskRegistrar, TaskRole,
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
    fenced_volume: Option<OwnedPrimaryDataVolume>,
    services: Option<ServiceHandle>,
}

/// A process that has stopped data admission and awaits one terminal trigger.
pub struct DrainingProcess(RunningProcess);

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
        self.begin_shutdown().finish(ShutdownTrigger::FirstSignal)
    }

    #[must_use]
    pub fn begin_shutdown(mut self) -> DrainingProcess {
        self.state.transition(ProcessPhase::Draining);
        let mut listener_close_failed = false;
        self.listeners.retain_mut(|listener| {
            if listener.endpoint().role().is_data() {
                listener_close_failed |= listener.close().is_err();
                false
            } else {
                true
            }
        });
        if listener_close_failed {
            self.state.transition(ProcessPhase::Stopping);
        }
        if self.instance.as_ref().is_some_and(|instance| {
            instance
                .lock()
                .map_or(true, |instance| instance.begin_shutdown().is_err())
        }) {
            self.state.transition(ProcessPhase::Stopping);
        }
        self.cancellation.cancel();
        DrainingProcess(self)
    }
}

impl DrainingProcess {
    #[must_use]
    pub fn health(&self) -> HealthState {
        self.0.health()
    }

    pub fn poll(&mut self) -> Result<bool, TaskFailure> {
        for task in &mut self.0.tasks {
            match task.poll_join()? {
                Some(TaskJoinOutcome::Joined) => {},
                Some(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal) => {
                    return Ok(false);
                },
                None => return Ok(false),
            }
        }
        Ok(true)
    }

    #[must_use]
    pub fn finish(mut self, trigger: ShutdownTrigger) -> ExitOutcome {
        if trigger != ShutdownTrigger::FirstSignal
            || self.0.state.health().phase() == ProcessPhase::Stopping
        {
            return self.0.abort_shutdown();
        }
        if trigger == ShutdownTrigger::FirstSignal {
            for task in &mut self.0.tasks {
                match task.join() {
                    Ok(TaskJoinOutcome::Joined) => {},
                    Ok(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal)
                    | Err(_) => return self.0.abort_shutdown(),
                }
            }
        }
        self.0.state.transition(ProcessPhase::Stopping);
        self.0.tasks.clear();
        if close_listeners(&mut self.0.listeners) {
            return self.0.abort_shutdown();
        }
        self.0.instance.take();
        self.0.fenced_volume.take();
        self.0.services.take();
        self.0.state.transition(ProcessPhase::Stopped);
        ExitOutcome::Graceful
    }
}

impl RunningProcess {
    fn abort_shutdown(&mut self) -> ExitOutcome {
        self.state.transition(ProcessPhase::Stopping);
        self.cancellation.cancel();
        for task in &mut self.tasks {
            match task.abort() {
                Ok(()) | Err(_) => {},
            }
        }
        self.tasks.clear();
        close_listeners(&mut self.listeners);
        self.instance.take();
        self.fenced_volume.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
        ExitOutcome::Forced
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        self.state.transition(ProcessPhase::Stopping);
        close_listeners(&mut self.listeners);
        for task in &mut self.tasks {
            match task.abort() {
                Ok(()) | Err(_) => {},
            }
        }
        self.tasks.clear();
        self.instance.take();
        self.fenced_volume.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
    }
}

fn close_listeners(listeners: &mut Vec<Box<dyn BoundListener>>) -> bool {
    let mut failed = false;
    for listener in listeners.iter_mut() {
        failed |= listener.close().is_err();
    }
    listeners.clear();
    failed
}

/// Sole owner of the runnable database lifecycle.
pub enum ApplicationRuntime {}

mod startup;
