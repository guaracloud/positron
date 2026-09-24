use std::net::SocketAddr;
use std::sync::Arc;

use positron_config::{ConfigurationDrift, ConfigurationDriftDisposition, EffectiveConfiguration};
use positron_kernel::OwnedPrimaryDataVolume;

use crate::health::ProcessState;
use crate::{
    BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BoundEndpoint, BoundListener,
    CatalogConfigurationPublication, ConfigurationReloadOutcome, ConfigurationRuntimeFailure,
    HealthState, InitializationPlan, InstanceBootstrap, ListenerFactory, ListenerRequest,
    ListenerRole, ProcessPhase, RegisteredTask, RunningTask, RuntimeConfiguration, ServiceHandle,
    TaskCancellation, TaskFailure, TaskJoinOutcome, TaskRegistrar, TaskRole,
};

/// Whether serving may initialize a provably empty instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationMode {
    ExistingOnly,
    InitializeIfEmpty,
}

/// A configuration-file-only plaintext API selection carried from the
/// composition root into startup. It is deliberately separate from public
/// administration and has no actor or credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicPlaintextApiStartupIntent {
    api_bind_address: SocketAddr,
}

impl PublicPlaintextApiStartupIntent {
    #[must_use]
    pub const fn configuration_file(api_bind_address: SocketAddr) -> Self {
        Self { api_bind_address }
    }

    #[must_use]
    pub const fn api_bind_address(self) -> SocketAddr {
        self.api_bind_address
    }
}

/// Fully typed inputs needed to establish the M1 database authorities.
pub struct ServeConfiguration {
    paths: BootstrapPaths,
    initialization: InitializationMode,
    max_registered_tenants: u16,
    public_plaintext_api_intent: Option<PublicPlaintextApiStartupIntent>,
    export_destination_resolver: Option<Arc<dyn positron_query::ExportDestinationResolver>>,
    effective_configuration: Option<Arc<EffectiveConfiguration>>,
    admission_group_planner: Option<Arc<dyn positron_ingest::AdmissionGroupPlanner>>,
}

impl ServeConfiguration {
    #[must_use]
    pub const fn new(paths: BootstrapPaths, initialization: InitializationMode) -> Self {
        Self {
            paths,
            initialization,
            max_registered_tenants: 2,
            public_plaintext_api_intent: None,
            export_destination_resolver: None,
            effective_configuration: None,
            admission_group_planner: None,
        }
    }

    /// Sets the configured ceiling for simultaneously registered governor tenant quotas.
    #[must_use]
    pub const fn with_max_registered_tenants(mut self, max_registered_tenants: u16) -> Self {
        self.max_registered_tenants = max_registered_tenants;
        self
    }

    #[must_use]
    pub fn with_admission_group_planner(
        mut self,
        planner: Arc<dyn positron_ingest::AdmissionGroupPlanner>,
    ) -> Self {
        self.admission_group_planner = Some(planner);
        self
    }

    /// Keeps the process ready while making an explicit public plaintext API
    /// selection continuously visible through its health state.
    #[must_use]
    pub const fn with_public_plaintext_api_intent(
        mut self,
        intent: PublicPlaintextApiStartupIntent,
    ) -> Self {
        self.public_plaintext_api_intent = Some(intent);
        self
    }

    #[must_use]
    pub fn with_export_destination_resolver(
        mut self,
        resolver: Arc<dyn positron_query::ExportDestinationResolver>,
    ) -> Self {
        self.export_destination_resolver = Some(resolver);
        self
    }

    /// Passes the canonical resolved Configuration Contract to the runtime.
    #[must_use]
    pub fn with_effective_configuration(
        mut self,
        configuration: Arc<EffectiveConfiguration>,
    ) -> Self {
        self.effective_configuration = Some(configuration);
        self
    }
}

impl std::fmt::Debug for ServeConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServeConfiguration")
            .field("paths", &self.paths)
            .field("initialization", &self.initialization)
            .field("max_registered_tenants", &self.max_registered_tenants)
            .field(
                "public_plaintext_api_intent",
                &self.public_plaintext_api_intent,
            )
            .field(
                "admission_group_planner",
                &self.admission_group_planner.is_some(),
            )
            .field(
                "export_destination_resolver",
                &self.export_destination_resolver.is_some(),
            )
            .field(
                "effective_configuration",
                &self.effective_configuration.is_some(),
            )
            .finish()
    }
}

/// Injected host boundaries; database modules remain concrete.
pub struct HostInputs<'host> {
    listeners: &'host dyn ListenerFactory,
    tasks: &'host dyn TaskRegistrar,
    recovery: &'host dyn RecoveryAttemptHost,
}

impl<'host> HostInputs<'host> {
    #[must_use]
    pub const fn new(
        listeners: &'host dyn ListenerFactory,
        tasks: &'host dyn TaskRegistrar,
    ) -> Self {
        Self {
            listeners,
            tasks,
            recovery: &BOUNDED_RECOVERY,
        }
    }

    #[must_use]
    pub const fn with_recovery(
        listeners: &'host dyn ListenerFactory,
        tasks: &'host dyn TaskRegistrar,
        recovery: &'host dyn RecoveryAttemptHost,
    ) -> Self {
        Self {
            listeners,
            tasks,
            recovery,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAttempt {
    number: u8,
    failure: BootstrapFailureCode,
    ownership_held: bool,
}

impl RecoveryAttempt {
    #[doc(hidden)]
    #[must_use]
    pub const fn for_test(number: u8) -> Self {
        Self {
            number,
            failure: BootstrapFailureCode::StorageUnavailable,
            ownership_held: false,
        }
    }

    #[must_use]
    pub const fn number(self) -> u8 {
        self.number
    }

    #[must_use]
    pub const fn failure(self) -> BootstrapFailureCode {
        self.failure
    }

    #[must_use]
    pub const fn ownership_held(self) -> bool {
        self.ownership_held
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    Retry,
    Exhausted,
    Terminate(ShutdownTrigger),
}

pub trait RecoveryAttemptHost {
    fn prerequisite_status(&self) -> Result<(), BootstrapFailureCode> {
        Ok(())
    }

    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision;
}

struct BoundedRecovery;
static BOUNDED_RECOVERY: BoundedRecovery = BoundedRecovery;

impl RecoveryAttemptHost for BoundedRecovery {
    fn after_failure(&self, attempt: RecoveryAttempt) -> RecoveryDecision {
        if attempt.number >= 32 {
            return RecoveryDecision::Exhausted;
        }
        std::thread::sleep(std::time::Duration::from_millis(
            10_u64.saturating_mul(u64::from(attempt.number)).min(100),
        ));
        RecoveryDecision::Retry
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
    InternalCleanupFailure(CleanupFailure),
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
    tasks: RunningTasks,
    cancellation: TaskCancellation,
    instance: Option<Arc<crate::InitializedInstance>>,
    fenced_volume: Option<OwnedPrimaryDataVolume>,
    services: Option<ServiceHandle>,
    configuration: Option<Arc<RuntimeConfiguration>>,
    configuration_publication: Option<CatalogConfigurationPublication>,
    cleanup: CleanupAccumulator,
    terminal_cleanup_complete: bool,
}

/// A process that has stopped data admission and awaits one terminal trigger.
pub struct DrainingProcess(RunningProcess);

type RunningTasks = Vec<(TaskRole, Box<dyn RunningTask>)>;

mod cleanup;
use cleanup::CleanupAccumulator;
pub use cleanup::{CleanupFailure, CleanupPrimary, CleanupRole};

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

    /// Returns the only complete Configuration generation visible to runtime
    /// consumers and authenticated inspection.
    #[must_use]
    pub fn configuration(&self) -> Option<Arc<RuntimeConfiguration>> {
        self.configuration.clone()
    }

    /// Publishes an already resolved candidate only through the joint Catalog
    /// and Governance Audit commit point.
    pub fn reload_configuration(
        &self,
        candidate: Arc<EffectiveConfiguration>,
    ) -> Result<ConfigurationReloadOutcome, ConfigurationRuntimeFailure> {
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let outcome = runtime.reload_with(
            Arc::clone(&candidate),
            self.configuration_publication
                .as_ref()
                .ok_or(ConfigurationRuntimeFailure::Unavailable)?,
        )?;
        Ok(outcome)
    }

    /// Records a rejected source document while retaining the current complete
    /// runtime configuration.
    pub fn record_invalid_configuration_reload(&self) -> Result<(), ConfigurationRuntimeFailure> {
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let active = runtime.observed()?;
        self.configuration_publication
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?
            .record_invalid(active.effective())
    }

    /// Reconciles ordinary desired-state drift through the durable reload
    /// path. Security, storage, and identity drift are instead durably
    /// reported and immediately stop data admission.
    pub fn reconcile_configuration_drift(
        &self,
        desired: Arc<EffectiveConfiguration>,
    ) -> Result<ConfigurationDrift, ConfigurationRuntimeFailure> {
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let drift = runtime.drift_against(Arc::clone(&desired))?;
        match drift.disposition() {
            ConfigurationDriftDisposition::None => Ok(drift),
            ConfigurationDriftDisposition::Reconcile => {
                self.reload_configuration(desired)?;
                Ok(drift)
            },
            ConfigurationDriftDisposition::Fence => {
                let drift = runtime.record_fenced_drift_with(
                    Arc::clone(&desired),
                    self.configuration_publication
                        .as_ref()
                        .ok_or(ConfigurationRuntimeFailure::Unavailable)?,
                )?;
                self.state.transition(ProcessPhase::Fenced);
                Ok(drift)
            },
        }
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
                if listener.close().is_err() && listener.close().is_err() {
                    listener_close_failed = true;
                    self.cleanup.record_listener(listener.endpoint().role());
                }
                false
            } else {
                true
            }
        });
        if listener_close_failed {
            self.state.transition(ProcessPhase::Stopping);
        }
        if self
            .services
            .as_ref()
            .is_some_and(|services| services.prepare_shutdown_schema_checkpoint().is_err())
        {
            self.cleanup.record_schema_checkpoint();
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
        for (_, task) in &mut self.0.tasks {
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
            for (_, task) in &mut self.0.tasks {
                match task.join() {
                    Ok(TaskJoinOutcome::Joined) => {},
                    Ok(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal)
                    | Err(_) => return self.0.abort_shutdown(),
                }
            }
        }
        self.0.tasks.clear();
        self.0.cleanup.cleanup_listeners(&mut self.0.listeners);
        if self.0.services.as_ref().is_some_and(|services| {
            services
                .publish_prepared_shutdown_schema_checkpoint()
                .is_err()
        }) {
            self.0.cleanup.record_schema_checkpoint();
        }
        if self
            .0
            .instance
            .as_ref()
            .is_some_and(|instance| instance.begin_shutdown().is_err())
        {
            return self.0.abort_shutdown();
        }
        self.0.state.transition(ProcessPhase::Stopping);
        self.0.cleanup.set_primary(ExitOutcome::Graceful);
        self.0.instance.take();
        self.0.fenced_volume.take();
        self.0.services.take();
        self.0.state.transition(ProcessPhase::Stopped);
        self.0.terminal_cleanup_complete = true;
        self.0.cleanup.outcome()
    }
}

impl RunningProcess {
    fn abort_shutdown(&mut self) -> ExitOutcome {
        self.state.transition(ProcessPhase::Stopping);
        self.cleanup.set_primary(ExitOutcome::Forced);
        self.cleanup
            .cleanup_tasks(&self.cancellation, &mut self.tasks);
        self.cleanup.cleanup_listeners(&mut self.listeners);
        self.instance.take();
        self.fenced_volume.take();
        self.services.take();
        self.state.transition(ProcessPhase::Stopped);
        self.terminal_cleanup_complete = true;
        self.cleanup.outcome()
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        if self.terminal_cleanup_complete {
            return;
        }
        self.state.transition(ProcessPhase::Stopping);
        self.cleanup
            .cleanup_tasks(&self.cancellation, &mut self.tasks);
        self.cleanup.cleanup_listeners(&mut self.listeners);
        self.instance.take();
        self.fenced_volume.take();
        self.services.take();
        self.state.transition(if self.cleanup.has_failures() {
            ProcessPhase::Fenced
        } else {
            ProcessPhase::Stopped
        });
    }
}

/// Sole owner of the runnable database lifecycle.
pub enum ApplicationRuntime {}

mod startup;
