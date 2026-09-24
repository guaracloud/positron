use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use positron_config::{
    ConfigurationDiffPlan, ConfigurationDrift, ConfigurationDriftDisposition,
    EffectiveConfiguration, NetworkListenerRole, NetworkTransport,
};
use positron_kernel::OwnedPrimaryDataVolume;
use sha2::{Digest, Sha256};

use crate::health::ProcessState;
use crate::{
    BootstrapFailure, BootstrapFailureCode, BootstrapPaths, BoundEndpoint, BoundListener,
    CatalogConfigurationPublication, ConfigurationReloadOutcome, ConfigurationRuntimeFailure,
    HealthState, InitializationPlan, InstanceBootstrap, ListenerFactory, ListenerGenerationFactory,
    ListenerRequest, ListenerRole, ProcessPhase, RegisteredTask, RunningTask, RuntimeConfiguration,
    ServiceHandle, TaskCancellation, TaskFailure, TaskJoinOutcome, TaskRegistrar, TaskRole,
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
    role: ListenerRole,
    listener_target: SocketAddr,
}

impl PublicPlaintextApiStartupIntent {
    #[must_use]
    pub const fn configuration_file(api_bind_address: SocketAddr) -> Self {
        Self::configuration_file_listener(ListenerRole::Api, api_bind_address)
    }

    #[must_use]
    pub const fn configuration_file_listener(
        role: ListenerRole,
        listener_target: SocketAddr,
    ) -> Self {
        Self {
            role,
            listener_target,
        }
    }

    #[must_use]
    pub const fn role(self) -> ListenerRole {
        self.role
    }

    #[must_use]
    pub const fn listener_target(self) -> SocketAddr {
        self.listener_target
    }

    #[must_use]
    pub const fn api_bind_address(self) -> SocketAddr {
        self.listener_target
    }
}

/// Fully typed inputs needed to establish the M1 database authorities.
pub struct ServeConfiguration {
    paths: BootstrapPaths,
    initialization: InitializationMode,
    max_registered_tenants: u16,
    plaintext_listener_intents: Vec<PublicPlaintextApiStartupIntent>,
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
            plaintext_listener_intents: Vec::new(),
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
    pub fn with_public_plaintext_api_intent(self, intent: PublicPlaintextApiStartupIntent) -> Self {
        self.with_plaintext_listener_intent(intent)
    }

    /// Carries one configuration-file plaintext opt-out into the joint
    /// startup publication path for its exact listener role.
    #[must_use]
    pub fn with_plaintext_listener_intent(
        mut self,
        intent: PublicPlaintextApiStartupIntent,
    ) -> Self {
        self.plaintext_listener_intents.push(intent);
        self
    }

    #[must_use]
    pub(crate) fn plaintext_listener_intents(&self) -> &[PublicPlaintextApiStartupIntent] {
        &self.plaintext_listener_intents
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

    pub(crate) fn drain_deadline(&self) -> std::time::Duration {
        self.effective_configuration.as_ref().map_or_else(
            || std::time::Duration::from_secs(30),
            |configuration| {
                std::time::Duration::from_secs(u64::from(configuration.shutdown_grace_seconds()))
            },
        )
    }
}

fn plaintext_listener_intents_for(
    configuration: &EffectiveConfiguration,
) -> Vec<PublicPlaintextApiStartupIntent> {
    [
        (NetworkListenerRole::Operations, ListenerRole::Operations),
        (NetworkListenerRole::Api, ListenerRole::Api),
        (NetworkListenerRole::OtlpGrpc, ListenerRole::OtlpGrpc),
        (NetworkListenerRole::OtlpHttp, ListenerRole::OtlpHttp),
        (NetworkListenerRole::LokiPush, ListenerRole::LokiPush),
    ]
    .into_iter()
    .filter_map(|(configuration_role, runtime_role)| {
        configuration
            .network_listener_profile(configuration_role)
            .filter(|profile| profile.transport() == NetworkTransport::PlaintextOptOut)
            .map(|profile| {
                PublicPlaintextApiStartupIntent::configuration_file_listener(
                    runtime_role,
                    profile.bind_address(),
                )
            })
    })
    .collect()
}

impl std::fmt::Debug for ServeConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServeConfiguration")
            .field("paths", &self.paths)
            .field("initialization", &self.initialization)
            .field("max_registered_tenants", &self.max_registered_tenants)
            .field(
                "plaintext_listener_intent_count",
                &self.plaintext_listener_intents.len(),
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
    listeners: Mutex<Vec<Box<dyn BoundListener>>>,
    listener_generation_factory: Option<Arc<dyn ListenerGenerationFactory>>,
    reload_lock: Mutex<()>,
    tasks: Mutex<RunningTasks>,
    listener_task_cancellations: Mutex<Vec<TaskCancellation>>,
    cancellation: TaskCancellation,
    instance: Option<Arc<crate::InitializedInstance>>,
    fenced_volume: Option<OwnedPrimaryDataVolume>,
    services: Option<ServiceHandle>,
    configuration: Option<Arc<RuntimeConfiguration>>,
    configuration_publication: Option<CatalogConfigurationPublication>,
    cleanup: CleanupAccumulator,
    drain_deadline: std::time::Duration,
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
            .field("listener_count", &self.listeners().len())
            .field("task_count", &self.tasks().len())
            .finish_non_exhaustive()
    }
}

impl RunningProcess {
    fn listeners(&self) -> MutexGuard<'_, Vec<Box<dyn BoundListener>>> {
        match self.listeners.lock() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn reload_lock(&self) -> MutexGuard<'_, ()> {
        match self.reload_lock.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn tasks(&self) -> MutexGuard<'_, RunningTasks> {
        match self.tasks.lock() {
            Ok(tasks) => tasks,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn cancel_listener_tasks(&self) {
        let cancellations = match self.listener_task_cancellations.lock() {
            Ok(cancellations) => cancellations,
            Err(poisoned) => poisoned.into_inner(),
        };
        for cancellation in &*cancellations {
            cancellation.cancel();
        }
    }

    fn take_listeners(&self) -> Vec<Box<dyn BoundListener>> {
        let mut listeners = self.listeners();
        std::mem::take(&mut *listeners)
    }

    #[must_use]
    pub fn health(&self) -> HealthState {
        self.state.health()
    }

    #[must_use]
    pub fn bound_endpoints(&self) -> Vec<BoundEndpoint> {
        self.listeners()
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
        let _reload = self.reload_lock();
        let runtime = self
            .configuration
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let publication = self
            .configuration_publication
            .as_ref()
            .ok_or(ConfigurationRuntimeFailure::Unavailable)?;
        let observed = runtime.observed()?;
        let plan = observed.effective().semantic_diff(&candidate).plan();
        if !matches!(
            plan,
            ConfigurationDiffPlan::DrainThenPublish | ConfigurationDiffPlan::NoChange
        ) {
            return runtime.reload_with(candidate, publication);
        }
        let Some(factory) = self.listener_generation_factory.as_ref() else {
            return runtime.reload_with(candidate, publication);
        };
        let staged = match factory.stage(&candidate, self.health(), self.services()) {
            Ok(staged) => staged,
            Err(_) => {
                if plan != ConfigurationDiffPlan::NoChange {
                    publication
                        .record_rejected_listener_staging(observed.effective(), &candidate)?;
                } else {
                    let listener_set_identity =
                        crate::configuration_catalog::configuration_digest(&candidate);
                    publication.record_tls_material_reload(
                        positron_governance::TlsMaterialReloadListenerSet::new(0b0011_1110)
                            .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)?,
                        positron_governance::TlsMaterialReloadOutcome::Rejected,
                        listener_set_identity,
                        Self::rejected_tls_attempt_identity(listener_set_identity),
                    )?;
                }
                return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
            },
        };
        if staged.prepare_tasks().is_err() {
            let material_identity = staged.material_identity();
            staged
                .discard()
                .map_err(|_| ConfigurationRuntimeFailure::ListenerUnavailable)?;
            if plan != ConfigurationDiffPlan::NoChange {
                publication.record_rejected_listener_staging(observed.effective(), &candidate)?;
            } else if let Some(material_identity) = material_identity {
                publication.record_tls_material_reload(
                    positron_governance::TlsMaterialReloadListenerSet::new(0b0011_1110)
                        .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)?,
                    positron_governance::TlsMaterialReloadOutcome::Rejected,
                    crate::configuration_catalog::configuration_digest(&candidate),
                    material_identity,
                )?;
            }
            return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
        }
        if plan == ConfigurationDiffPlan::NoChange {
            let material_identity = staged
                .material_identity()
                .ok_or(ConfigurationRuntimeFailure::ListenerUnavailable)?;
            publication.record_tls_material_reload(
                positron_governance::TlsMaterialReloadListenerSet::new(0b0011_1110)
                    .map_err(|_| ConfigurationRuntimeFailure::PublicationUnavailable)?,
                positron_governance::TlsMaterialReloadOutcome::Applied,
                crate::configuration_catalog::configuration_digest(&candidate),
                material_identity,
            )?;
        }
        let outcome = match if plan == ConfigurationDiffPlan::NoChange {
            runtime.reload_with(Arc::clone(&candidate), publication)
        } else {
            runtime.publish_staged_listener_reload(Arc::clone(&candidate), publication)
        } {
            Ok(outcome) => {
                self.state
                    .set_plaintext_listener_warnings(&plaintext_listener_intents_for(&candidate));
                outcome
            },
            Err(error) => {
                staged
                    .discard()
                    .map_err(|_| ConfigurationRuntimeFailure::ListenerUnavailable)?;
                return Err(error);
            },
        };
        let mut retired = {
            let mut active = self.listeners();
            std::mem::take(&mut *active)
        };
        let mut retired_tasks = {
            let mut active = self.tasks();
            std::mem::take(&mut *active)
        };
        let retired_cancellations = {
            let mut active = match self.listener_task_cancellations.lock() {
                Ok(cancellations) => cancellations,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *active)
        };
        let retirement_deadline = std::time::Instant::now() + self.drain_deadline;
        if close_listeners(&mut retired).is_err() {
            let abort_failed = abort_retired_tasks(&mut retired_tasks).is_err();
            self.state.transition(ProcessPhase::Fenced);
            if abort_failed {
                return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
            }
            return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
        }
        staged.open_admission();
        let (successor, successor_tasks, successor_cancellation) = staged.into_active();
        {
            let mut active = self.listeners();
            *active = successor;
        }
        {
            let mut active = self.tasks();
            *active = successor_tasks;
        }
        if let Some(cancellation) = successor_cancellation {
            let mut active = match self.listener_task_cancellations.lock() {
                Ok(cancellations) => cancellations,
                Err(poisoned) => poisoned.into_inner(),
            };
            active.push(cancellation);
        }
        for cancellation in retired_cancellations {
            cancellation.cancel();
        }
        if drain_listeners_until(&mut retired, retirement_deadline).is_err()
            || join_retired_tasks_until(&mut retired_tasks, retirement_deadline).is_err()
        {
            let abort_failed = abort_retired_tasks(&mut retired_tasks).is_err();
            self.state.transition(ProcessPhase::Fenced);
            if abort_failed {
                return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
            }
            return Err(ConfigurationRuntimeFailure::ListenerUnavailable);
        }
        Ok(outcome)
    }

    fn rejected_tls_attempt_identity(listener_set_identity: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"positron/tls-material-reload/rejected-attempt/v1");
        hasher.update(listener_set_identity);
        hasher.finalize().into()
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
        if let Some(drift) = runtime.clear_matching_desired_configuration(&desired)? {
            return Ok(drift);
        }
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
        let failed_roles = {
            let mut listeners = self.listeners();
            let mut failed_roles = Vec::new();
            listeners.retain_mut(|listener| {
                if listener.endpoint().role().is_data() {
                    if listener.close().is_err() {
                        failed_roles.push(listener.endpoint().role());
                    }
                    false
                } else {
                    true
                }
            });
            failed_roles
        };
        for role in failed_roles {
            self.cleanup.record_listener(role);
        }
        if self.cleanup.has_failures() {
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
        self.cancel_listener_tasks();
        DrainingProcess(self)
    }
}

fn close_listeners(listeners: &mut [Box<dyn BoundListener>]) -> Result<(), ()> {
    for listener in &mut *listeners {
        listener.close().map_err(|_| ())?;
    }
    Ok(())
}

fn drain_listeners_until(
    listeners: &mut [Box<dyn BoundListener>],
    deadline: std::time::Instant,
) -> Result<(), ()> {
    for listener in listeners {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return Err(());
        };
        if !listener.drain_within(remaining).map_err(|_| ())? {
            return Err(());
        }
    }
    Ok(())
}

fn join_retired_tasks_until(
    tasks: &mut RunningTasks,
    deadline: std::time::Instant,
) -> Result<(), ()> {
    for (_, task) in tasks {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return Err(());
        };
        match task.join_within(remaining).map_err(|_| ())? {
            TaskJoinOutcome::Joined => {},
            TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal => return Err(()),
        }
    }
    Ok(())
}

fn abort_retired_tasks(tasks: &mut RunningTasks) -> Result<(), ()> {
    for (_, task) in tasks {
        task.abort().map_err(|_| ())?;
    }
    Ok(())
}

impl DrainingProcess {
    #[must_use]
    pub fn health(&self) -> HealthState {
        self.0.health()
    }

    pub fn poll(&mut self) -> Result<bool, TaskFailure> {
        let tasks = self
            .0
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (_, task) in &mut *tasks {
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
            let deadline = std::time::Instant::now() + self.0.drain_deadline;
            let tasks = self
                .0
                .tasks
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (_, task) in &mut *tasks {
                let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
                else {
                    return self.0.abort_shutdown();
                };
                match task.join_within(remaining) {
                    Ok(TaskJoinOutcome::Joined) => {},
                    Ok(TaskJoinOutcome::DeadlineExpired | TaskJoinOutcome::SecondSignal)
                    | Err(_) => return self.0.abort_shutdown(),
                }
            }
        }
        self.0
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let mut listeners = self.0.take_listeners();
        self.0.cleanup.cleanup_listeners(&mut listeners);
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
        self.cancel_listener_tasks();
        self.cleanup.cleanup_tasks(
            &self.cancellation,
            self.tasks
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut listeners = self.take_listeners();
        self.cleanup.cleanup_listeners(&mut listeners);
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
        self.cancel_listener_tasks();
        self.cleanup.cleanup_tasks(
            &self.cancellation,
            self.tasks
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let listeners = match self.listeners.get_mut() {
            Ok(listeners) => listeners,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.cleanup.cleanup_listeners(listeners);
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
