//! Bounded coordination of Storage Kernel background work.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::{
    CatalogObject, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension,
    ResourceReservation, StorageKernelResourceAuthority, WorkClaim, WorkKind,
};

const MAX_MAINTENANCE_TASKS: usize = 128;
const MAX_TASK_OBJECTS: usize = 16;
const MAX_CHECKPOINT_BYTES: usize = 4_096;
const MAX_PRIORITY_DISPATCH_LEAD: u64 = 2;

/// A stable, caller-supplied identity for one idempotent maintenance task.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MaintenanceTaskId([u8; 16]);

impl MaintenanceTaskId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, MaintenanceFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Closed Release 1 maintenance work classes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenanceTaskClass {
    ActiveSegmentRoll,
    Compaction,
    RetentionPublication,
    RetentionReclamation,
    CatalogReclamation,
    OrphanReclamation,
    IntegrityScrub,
    QuarantineFollowUp,
    SchemaStatistics,
    SchemaPromotion,
    SchemaDemotion,
    GovernanceAuditCheckpoint,
    KeyRewrap,
    EnvelopeVerification,
    Migration,
    RepositoryVerification,
    RepositoryCleanup,
    BackupSnapshot,
    DurableExport,
    SnapshotLeaseExpiry,
    CompletedOperationExpiry,
    TenantPurge,
}

impl MaintenanceTaskClass {
    const fn deferrable(self) -> bool {
        matches!(
            self,
            Self::Compaction
                | Self::SchemaPromotion
                | Self::SchemaDemotion
                | Self::RepositoryVerification
                | Self::BackupSnapshot
                | Self::DurableExport
        )
    }

    const fn destructive(self) -> bool {
        matches!(
            self,
            Self::RetentionPublication
                | Self::RetentionReclamation
                | Self::CatalogReclamation
                | Self::OrphanReclamation
                | Self::RepositoryCleanup
                | Self::SnapshotLeaseExpiry
                | Self::CompletedOperationExpiry
        )
    }
}

/// The bounded task scope used for fairness and conflicts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenanceScope {
    System,
    Tenant {
        tenant: TenantId,
        signal: Option<SignalKind>,
        shard: Option<VirtualShardId>,
    },
}

impl MaintenanceScope {
    #[must_use]
    pub const fn system() -> Self {
        Self::System
    }

    #[must_use]
    pub const fn tenant(tenant: TenantId) -> Self {
        Self::Tenant {
            tenant,
            signal: None,
            shard: None,
        }
    }

    #[must_use]
    pub const fn segment(tenant: TenantId, signal: SignalKind, shard: VirtualShardId) -> Self {
        Self::Tenant {
            tenant,
            signal: Some(signal),
            shard: Some(shard),
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> Option<TenantId> {
        match self {
            Self::System => None,
            Self::Tenant { tenant, .. } => Some(tenant),
        }
    }
}

/// Opaque immutable input or copy-on-write output identity used in conflicts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MaintenanceObjectId([u8; 32]);

impl MaintenanceObjectId {
    pub fn new(bytes: [u8; 32]) -> Result<Self, MaintenanceFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// The event provenance used to gate unsafe clock-derived work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTrigger {
    Event,
    Scheduled,
    AgeDerived,
}

/// Scheduling urgency. Fairness still selects the least-served eligible tenant.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenancePriority {
    Ordinary,
    Required,
    Urgent,
}

/// Catalog and administration state that must still match at task start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenancePreconditions {
    catalog_generation: u64,
    resource_generation: u64,
}

impl MaintenancePreconditions {
    pub fn new(
        catalog_generation: u64,
        resource_generation: u64,
    ) -> Result<Self, MaintenanceFailure> {
        if resource_generation == 0 {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            catalog_generation,
            resource_generation,
        })
    }

    #[must_use]
    pub const fn catalog_generation(self) -> u64 {
        self.catalog_generation
    }
    #[must_use]
    pub const fn resource_generation(self) -> u64 {
        self.resource_generation
    }
}

/// A bounded durable progress point. Its opaque payload is written by the task handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceCheckpoint {
    sequence: u64,
    completed_inputs: u32,
    opaque_progress: Vec<u8>,
}

impl MaintenanceCheckpoint {
    pub fn new(
        sequence: u64,
        completed_inputs: u32,
        opaque_progress: Vec<u8>,
    ) -> Result<Self, MaintenanceFailure> {
        if sequence == 0 || opaque_progress.len() > MAX_CHECKPOINT_BYTES {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            sequence,
            completed_inputs,
            opaque_progress,
        })
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn completed_inputs(&self) -> u32 {
        self.completed_inputs
    }
    #[must_use]
    pub fn opaque_progress(&self) -> &[u8] {
        &self.opaque_progress
    }
}

/// Public lifecycle state for one submitted maintenance identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTaskPhase {
    Queued,
    Running,
    Deferred,
    Cancelled,
    Succeeded,
    Failed,
}

/// A bounded maintenance request submitted through the sole coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTask {
    identity: MaintenanceTaskId,
    class: MaintenanceTaskClass,
    scope: MaintenanceScope,
    trigger: MaintenanceTrigger,
    priority: MaintenancePriority,
    preconditions: MaintenancePreconditions,
    inputs: Vec<MaintenanceObjectId>,
    outputs: Vec<MaintenanceObjectId>,
    reservations: ResourceAmounts,
}

impl MaintenanceTask {
    #[must_use]
    pub fn new(identity: MaintenanceTaskId, class: MaintenanceTaskClass) -> Self {
        // A system-scoped task with a fixed, non-empty reservation is useful
        // only for the small set of catalog-owned maintenance tests. Production
        // submitters use `with_contract` to state their actual scope and peak.
        Self {
            identity,
            class,
            scope: MaintenanceScope::System,
            trigger: MaintenanceTrigger::Event,
            priority: MaintenancePriority::Ordinary,
            preconditions: MaintenancePreconditions {
                catalog_generation: 0,
                resource_generation: 1,
            },
            inputs: Vec::new(),
            outputs: Vec::new(),
            reservations: ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_contract(
        identity: MaintenanceTaskId,
        class: MaintenanceTaskClass,
        scope: MaintenanceScope,
        trigger: MaintenanceTrigger,
        priority: MaintenancePriority,
        preconditions: MaintenancePreconditions,
        mut inputs: Vec<MaintenanceObjectId>,
        mut outputs: Vec<MaintenanceObjectId>,
        reservations: ResourceAmounts,
    ) -> Result<Self, MaintenanceFailure> {
        if inputs.len() > MAX_TASK_OBJECTS
            || outputs.len() > MAX_TASK_OBJECTS
            || ResourceDimension::ALL
                .iter()
                .all(|dimension| reservations.get(*dimension) == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        inputs.sort_unstable();
        outputs.sort_unstable();
        if inputs.windows(2).any(|pair| pair[0] == pair[1])
            || outputs.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            identity,
            class,
            scope,
            trigger,
            priority,
            preconditions,
            inputs,
            outputs,
            reservations,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> MaintenanceTaskId {
        self.identity
    }

    #[must_use]
    pub const fn class(&self) -> MaintenanceTaskClass {
        self.class
    }

    #[must_use]
    pub const fn scope(&self) -> MaintenanceScope {
        self.scope
    }
    #[must_use]
    pub const fn trigger(&self) -> MaintenanceTrigger {
        self.trigger
    }
    #[must_use]
    pub const fn priority(&self) -> MaintenancePriority {
        self.priority
    }
    #[must_use]
    pub const fn preconditions(&self) -> MaintenancePreconditions {
        self.preconditions
    }
    #[must_use]
    pub fn inputs(&self) -> &[MaintenanceObjectId] {
        &self.inputs
    }
    #[must_use]
    pub fn outputs(&self) -> &[MaintenanceObjectId] {
        &self.outputs
    }
    #[must_use]
    pub const fn reservations(&self) -> ResourceAmounts {
        self.reservations
    }
}

/// Typed rejection from the maintenance control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceFailure {
    InvalidInput,
    CapacityExceeded,
    ConcurrentAccess,
    UnknownTask,
    InvalidTransition,
    PreconditionFailed,
    Paused,
    ResourceAdmissionRefused,
    CatalogUnavailable,
}

/// The only scheduler for background Storage Kernel work.
pub struct MaintenanceCoordinator {
    state: Mutex<CoordinatorState>,
}

#[derive(Clone)]
struct CoordinatorState {
    tasks: BTreeMap<MaintenanceTaskId, TaskState>,
    windows: BTreeSet<MaintenanceTaskClass>,
    fairness: BTreeMap<MaintenanceScope, u64>,
}

#[derive(Clone)]
struct TaskState {
    task: MaintenanceTask,
    phase: MaintenanceTaskPhase,
    submitted_at: u64,
    checkpoint: Option<MaintenanceCheckpoint>,
    pause_until: Option<u64>,
    cancellation_requested: bool,
    dispatches: u64,
}

/// Read-only task status. It exposes no unbounded object identifiers in telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTaskStatus {
    task: MaintenanceTask,
    phase: MaintenanceTaskPhase,
    submitted_at: u64,
    checkpoint: Option<MaintenanceCheckpoint>,
    pause_until: Option<u64>,
    cancellation_requested: bool,
}

/// A live Resource Governor grant attached to a running task. The coordinator
/// never manufactures capacity and the grant drops on every handler path.
pub enum MaintenanceReservation<'authority> {
    Ordinary(ResourceReservation<'authority>),
    Recovery(ResourceReservation<'authority>),
}

impl MaintenanceReservation<'_> {
    #[must_use]
    pub fn granted(&self) -> ResourceAmounts {
        match self {
            Self::Ordinary(reservation) | Self::Recovery(reservation) => reservation.granted(),
        }
    }
}

/// A task selected by the coordinator after its complete peak reservation was admitted.
pub struct MaintenanceExecution<'authority> {
    task: MaintenanceTask,
    reservation: MaintenanceReservation<'authority>,
}

impl MaintenanceExecution<'_> {
    #[must_use]
    pub fn task(&self) -> &MaintenanceTask {
        &self.task
    }
    #[must_use]
    pub fn reservation(&self) -> &MaintenanceReservation<'_> {
        &self.reservation
    }
}

/// One bounded, versioned Catalog payload for task recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTaskRecord(Vec<u8>);

impl MaintenanceTaskRecord {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the immutable Catalog object that a task-control transaction
    /// publishes alongside its handler checkpoint or terminal outcome.
    pub fn catalog_object(&self) -> Result<CatalogObject, MaintenanceFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.0.len())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        bytes.extend_from_slice(&self.0);
        CatalogObject::new(bytes).map_err(|_| MaintenanceFailure::CapacityExceeded)
    }
}

impl MaintenanceTaskStatus {
    #[must_use]
    pub fn task(&self) -> &MaintenanceTask {
        &self.task
    }
    #[must_use]
    pub const fn phase(&self) -> MaintenanceTaskPhase {
        self.phase
    }
    #[must_use]
    pub const fn submitted_at(&self) -> u64 {
        self.submitted_at
    }
    #[must_use]
    pub fn checkpoint(&self) -> Option<&MaintenanceCheckpoint> {
        self.checkpoint.as_ref()
    }
    #[must_use]
    pub const fn pause_until(&self) -> Option<u64> {
        self.pause_until
    }
    #[must_use]
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }
}

impl MaintenanceCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CoordinatorState {
                tasks: BTreeMap::new(),
                windows: BTreeSet::new(),
                fairness: BTreeMap::new(),
            }),
        }
    }

    /// Attaches a retry with the same stable identity to its existing work.
    pub fn submit(&self, task: MaintenanceTask) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_at(task, 0)
    }

    /// Registers task work at a monotonic scheduler instant. Queue storage is
    /// bounded and retrying the same contract returns its original identity.
    pub fn submit_at(
        &self,
        task: MaintenanceTask,
        now: u64,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if let Some(existing) = state.tasks.get(&task.identity) {
            if existing.task != task {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            return Ok(existing.task.clone());
        }
        if state.tasks.len() >= MAX_MAINTENANCE_TASKS {
            return Err(MaintenanceFailure::CapacityExceeded);
        }
        state.tasks.insert(
            task.identity,
            TaskState {
                task: task.clone(),
                phase: MaintenanceTaskPhase::Queued,
                submitted_at: now,
                checkpoint: None,
                pause_until: None,
                cancellation_requested: false,
                dispatches: 0,
            },
        );
        Ok(task)
    }

    /// Defers only the product-declared optional classes. Required work stays
    /// schedulable while a Window exists.
    pub fn set_window(
        &self,
        deferred: impl IntoIterator<Item = MaintenanceTaskClass>,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut classes = BTreeSet::new();
        for class in deferred {
            if !class.deferrable() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            classes.insert(class);
        }
        state.windows = classes;
        Ok(())
    }

    /// Pauses one optional task until a finite monotonic deadline.
    pub fn pause(
        &self,
        identity: MaintenanceTaskId,
        resource_generation: u64,
        until: u64,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if until <= now {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if !task.task.class.deferrable()
            || task.task.preconditions.resource_generation != resource_generation
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        if !matches!(
            task.phase,
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Deferred
        ) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Deferred;
        task.pause_until = Some(until);
        Ok(())
    }

    pub fn resume(&self, identity: MaintenanceTaskId) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Deferred {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Queued;
        task.pause_until = None;
        Ok(())
    }

    /// Requests cooperative cancellation. A running handler observes this at
    /// its existing safe checkpoint; no output is made current by cancellation.
    pub fn cancel(&self, identity: MaintenanceTaskId) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        match task.phase {
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Deferred => {
                task.phase = MaintenanceTaskPhase::Cancelled;
            },
            MaintenanceTaskPhase::Running => task.cancellation_requested = true,
            MaintenanceTaskPhase::Cancelled
            | MaintenanceTaskPhase::Succeeded
            | MaintenanceTaskPhase::Failed => {},
        }
        Ok(())
    }

    /// Selects one eligible task, applying expiries, windows, ClockUncertain
    /// and explicit conflict exclusion before a handler receives the task.
    pub fn start_next(
        &self,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceTask>, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        for task in state.tasks.values_mut() {
            if task.phase == MaintenanceTaskPhase::Deferred
                && task.pause_until.is_some_and(|until| until <= now)
            {
                task.phase = MaintenanceTaskPhase::Queued;
                task.pause_until = None;
            }
        }
        let running = state
            .tasks
            .values()
            .filter(|task| task.phase == MaintenanceTaskPhase::Running)
            .map(|task| task.task.clone())
            .collect::<Vec<_>>();
        let candidate = state
            .tasks
            .values()
            .filter(|task| {
                let clock_blocks = clock_uncertain
                    && task.task.trigger == MaintenanceTrigger::AgeDerived
                    && task.task.class.destructive();
                let conflicts = running
                    .iter()
                    .any(|active| tasks_conflict(&task.task, active));
                task.phase == MaintenanceTaskPhase::Queued
                    && !state.windows.contains(&task.task.class)
                    && !clock_blocks
                    && !conflicts
            })
            .min_by(|left, right| scheduling_order(left, right, &state.fairness));
        let Some(identity) = candidate.map(|task| task.task.identity) else {
            return Ok(None);
        };
        let scope = {
            let task = state
                .tasks
                .get_mut(&identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            task.phase = MaintenanceTaskPhase::Running;
            task.dispatches = task
                .dispatches
                .checked_add(1)
                .ok_or(MaintenanceFailure::CapacityExceeded)?;
            task.task.scope
        };
        let scope_dispatches = state.fairness.entry(scope).or_insert(0);
        *scope_dispatches = scope_dispatches
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        Ok(state.tasks.get(&identity).map(|task| task.task.clone()))
    }

    /// Selects and reserves one task in one operation. A refusal returns the
    /// task to the bounded queue, preserving its identity and checkpoint for a
    /// later wakeup instead of creating a retry loop or a second scheduler.
    pub fn start_next_with_reservation<'authority>(
        &self,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        let Some(task) = self.start_next(now, clock_uncertain)? else {
            return Ok(None);
        };
        let reservation = reserve_task(authority, &task)
            .map_err(|_| MaintenanceFailure::ResourceAdmissionRefused);
        match reservation {
            Ok(reservation) => Ok(Some(MaintenanceExecution { task, reservation })),
            Err(failure) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
                if let Some(stored) = state.tasks.get_mut(&task.identity)
                    && stored.phase == MaintenanceTaskPhase::Running
                {
                    stored.phase = MaintenanceTaskPhase::Queued;
                }
                Err(failure)
            },
        }
    }

    pub fn checkpoint(
        &self,
        identity: MaintenanceTaskId,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || checkpoint.completed_inputs as usize > task.task.inputs.len()
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        if task
            .checkpoint
            .as_ref()
            .is_some_and(|previous| previous.sequence >= checkpoint.sequence)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        task.checkpoint = Some(checkpoint);
        Ok(())
    }

    pub fn complete(
        &self,
        identity: MaintenanceTaskId,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = if task.cancellation_requested {
            MaintenanceTaskPhase::Cancelled
        } else if succeeded {
            MaintenanceTaskPhase::Succeeded
        } else {
            MaintenanceTaskPhase::Failed
        };
        Ok(())
    }

    /// Crash recovery releases ephemeral reservations and makes any nonterminal
    /// checkpointed task eligible to resume through its same stable identity.
    pub fn recover_after_crash(&self) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        for task in state.tasks.values_mut() {
            if task.phase == MaintenanceTaskPhase::Running {
                task.phase = MaintenanceTaskPhase::Queued;
                task.cancellation_requested = false;
            }
        }
        Ok(())
    }

    pub fn status(
        &self,
        identity: MaintenanceTaskId,
    ) -> Result<MaintenanceTaskStatus, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        Ok(MaintenanceTaskStatus {
            task: task.task.clone(),
            phase: task.phase,
            submitted_at: task.submitted_at,
            checkpoint: task.checkpoint.clone(),
            pause_until: task.pause_until,
            cancellation_requested: task.cancellation_requested,
        })
    }

    pub fn durable_records(&self) -> Result<Vec<MaintenanceTaskRecord>, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state.tasks.values().map(encode_record).collect()
    }

    pub fn restore(
        records: impl IntoIterator<Item = MaintenanceTaskRecord>,
    ) -> Result<Self, MaintenanceFailure> {
        let coordinator = Self::new();
        for record in records {
            let mut state = decode_record(record.as_bytes())?;
            if state.phase == MaintenanceTaskPhase::Running {
                state.phase = MaintenanceTaskPhase::Queued;
                state.cancellation_requested = false;
            }
            let mut inner = coordinator
                .state
                .lock()
                .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
            if inner.tasks.len() >= MAX_MAINTENANCE_TASKS
                || inner.tasks.insert(state.task.identity, state).is_some()
            {
                return Err(MaintenanceFailure::CapacityExceeded);
            }
        }
        Ok(coordinator)
    }
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_maintenance_stateful(data: &[u8]) {
    if data.len() > 16_384 {
        return;
    }
    let _ = MaintenanceCoordinator::restore([MaintenanceTaskRecord(data.to_vec())]);
    let coordinator = MaintenanceCoordinator::new();
    let mut identity = [1_u8; 16];
    if let Some(value) = data.first() {
        identity[0] = (*value).max(1);
    }
    let Ok(identity) = MaintenanceTaskId::new(identity) else {
        return;
    };
    let class = match data.get(1).copied().unwrap_or_default() % 4 {
        0 => MaintenanceTaskClass::Compaction,
        1 => MaintenanceTaskClass::RetentionPublication,
        2 => MaintenanceTaskClass::SnapshotLeaseExpiry,
        _ => MaintenanceTaskClass::SchemaPromotion,
    };
    let task = MaintenanceTask::new(identity, class);
    let _ = coordinator.submit_at(task, u64::from(data.get(2).copied().unwrap_or_default()));
    let uncertain = data.get(3).is_some_and(|value| value & 1 == 1);
    let _ = coordinator.start_next(
        u64::from(data.get(4).copied().unwrap_or_default()),
        uncertain,
    );
    let _ = coordinator.cancel(identity);
    let _ = coordinator.recover_after_crash();
    let _ = coordinator.durable_records();
}

fn reserve_task<'authority>(
    authority: &'authority StorageKernelResourceAuthority,
    task: &MaintenanceTask,
) -> Result<MaintenanceReservation<'authority>, ()> {
    let recovery_kind = match task.class {
        MaintenanceTaskClass::ActiveSegmentRoll
        | MaintenanceTaskClass::GovernanceAuditCheckpoint => {
            Some(RecoveryWorkKind::DurabilityCompletion)
        },
        MaintenanceTaskClass::Compaction if task.priority == MaintenancePriority::Urgent => {
            Some(RecoveryWorkKind::EmergencyCompaction)
        },
        MaintenanceTaskClass::RetentionPublication | MaintenanceTaskClass::RetentionReclamation => {
            Some(RecoveryWorkKind::Retention)
        },
        MaintenanceTaskClass::TenantPurge => Some(RecoveryWorkKind::Purge),
        MaintenanceTaskClass::IntegrityScrub
        | MaintenanceTaskClass::QuarantineFollowUp
        | MaintenanceTaskClass::CatalogReclamation
        | MaintenanceTaskClass::OrphanReclamation
        | MaintenanceTaskClass::KeyRewrap
        | MaintenanceTaskClass::EnvelopeVerification
        | MaintenanceTaskClass::Migration => Some(RecoveryWorkKind::Repair),
        _ => None,
    };
    if let Some(kind) = recovery_kind {
        let claim = match task.scope.tenant_id() {
            Some(tenant) => RecoveryWorkClaim::tenant(tenant, kind, task.reservations),
            None => RecoveryWorkClaim::system(kind, task.reservations),
        }
        .map_err(|_| ())?;
        return authority
            .recovery()
            .reserve(claim)
            .map(MaintenanceReservation::Recovery)
            .map_err(|_| ());
    }
    let tenant = task.scope.tenant_id().ok_or(())?;
    let claim = WorkClaim::tenant(
        tenant,
        WorkKind::OrdinaryMaintenanceBackup,
        task.reservations,
    )
    .map_err(|_| ())?;
    authority
        .governor()
        .reserve(claim)
        .map(MaintenanceReservation::Ordinary)
        .map_err(|_| ())
}

fn tasks_conflict(left: &MaintenanceTask, right: &MaintenanceTask) -> bool {
    if left.scope != right.scope {
        return false;
    }
    left.inputs.iter().any(|object| {
        right.inputs.binary_search(object).is_ok() || right.outputs.binary_search(object).is_ok()
    }) || left.outputs.iter().any(|object| {
        right.inputs.binary_search(object).is_ok() || right.outputs.binary_search(object).is_ok()
    }) || matches!(left.class, MaintenanceTaskClass::TenantPurge)
        || matches!(right.class, MaintenanceTaskClass::TenantPurge)
}

fn scheduling_order(
    left: &TaskState,
    right: &TaskState,
    fairness: &BTreeMap<MaintenanceScope, u64>,
) -> std::cmp::Ordering {
    let left_dispatches = fairness.get(&left.task.scope).copied().unwrap_or(0);
    let right_dispatches = fairness.get(&right.task.scope).copied().unwrap_or(0);
    let fairness_order = left_dispatches.abs_diff(right_dispatches);
    if fairness_order >= MAX_PRIORITY_DISPATCH_LEAD {
        return left_dispatches.cmp(&right_dispatches);
    }
    right
        .task
        .priority
        .cmp(&left.task.priority)
        .then_with(|| left.dispatches.cmp(&right.dispatches))
        .then_with(|| left.submitted_at.cmp(&right.submitted_at))
        .then_with(|| left.task.identity.cmp(&right.task.identity))
}

const RECORD_MAGIC: &[u8; 8] = b"PMTC0001";

fn encode_record(state: &TaskState) -> Result<MaintenanceTaskRecord, MaintenanceFailure> {
    let task = &state.task;
    let checkpoint_bytes = state
        .checkpoint
        .as_ref()
        .map_or(0, |checkpoint| checkpoint.opaque_progress.len());
    let objects = task
        .inputs
        .len()
        .checked_add(task.outputs.len())
        .ok_or(MaintenanceFailure::CapacityExceeded)?;
    let capacity = RECORD_MAGIC
        .len()
        .checked_add(16 + 3 + 16 + 6 + 16 + 1 + 1 + 8 + 1 + 8)
        .and_then(|size| size.checked_add(objects.checked_mul(32)?))
        .and_then(|size| {
            size.checked_add(11 * 8 + 1 + 8 + 1 + 1 + 8 + 1 + 8 + 4 + 4 + checkpoint_bytes)
        })
        .ok_or(MaintenanceFailure::CapacityExceeded)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    bytes.extend_from_slice(RECORD_MAGIC);
    bytes.extend_from_slice(&task.identity.to_bytes());
    bytes.push(class_code(task.class));
    encode_scope(&mut bytes, task.scope);
    bytes.push(trigger_code(task.trigger));
    bytes.push(priority_code(task.priority));
    push_u64(&mut bytes, task.preconditions.catalog_generation);
    push_u64(&mut bytes, task.preconditions.resource_generation);
    bytes.push(u8::try_from(task.inputs.len()).map_err(|_| MaintenanceFailure::CapacityExceeded)?);
    for input in &task.inputs {
        bytes.extend_from_slice(&input.to_bytes());
    }
    bytes.push(u8::try_from(task.outputs.len()).map_err(|_| MaintenanceFailure::CapacityExceeded)?);
    for output in &task.outputs {
        bytes.extend_from_slice(&output.to_bytes());
    }
    for dimension in ResourceDimension::ALL {
        push_u64(&mut bytes, task.reservations.get(dimension));
    }
    bytes.push(phase_code(state.phase));
    push_u64(&mut bytes, state.submitted_at);
    bytes.push(u8::from(state.pause_until.is_some()));
    push_u64(&mut bytes, state.pause_until.unwrap_or(0));
    bytes.push(u8::from(state.cancellation_requested));
    push_u64(&mut bytes, state.dispatches);
    bytes.push(u8::from(state.checkpoint.is_some()));
    if let Some(checkpoint) = &state.checkpoint {
        push_u64(&mut bytes, checkpoint.sequence);
        push_u32(&mut bytes, checkpoint.completed_inputs);
        push_u32(
            &mut bytes,
            u32::try_from(checkpoint.opaque_progress.len())
                .map_err(|_| MaintenanceFailure::CapacityExceeded)?,
        );
        bytes.extend_from_slice(&checkpoint.opaque_progress);
    }
    Ok(MaintenanceTaskRecord(bytes))
}

fn decode_record(bytes: &[u8]) -> Result<TaskState, MaintenanceFailure> {
    let mut cursor = RecordCursor::new(bytes);
    if cursor.take_exact(RECORD_MAGIC.len())? != RECORD_MAGIC {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let identity = MaintenanceTaskId::new(cursor.array_16()?)?;
    let class = class_from_code(cursor.byte()?)?;
    let scope = decode_scope(&mut cursor)?;
    let trigger = trigger_from_code(cursor.byte()?)?;
    let priority = priority_from_code(cursor.byte()?)?;
    let preconditions = MaintenancePreconditions::new(cursor.u64()?, cursor.u64()?)?;
    let inputs = decode_objects(&mut cursor)?;
    let outputs = decode_objects(&mut cursor)?;
    let mut amounts = [0_u64; 11];
    for slot in &mut amounts {
        *slot = cursor.u64()?;
    }
    let task = MaintenanceTask::with_contract(
        identity,
        class,
        scope,
        trigger,
        priority,
        preconditions,
        inputs,
        outputs,
        ResourceAmounts::new(amounts),
    )?;
    let phase = phase_from_code(cursor.byte()?)?;
    let submitted_at = cursor.u64()?;
    let pause_until = match cursor.byte()? {
        0 => {
            let _ = cursor.u64()?;
            None
        },
        1 => Some(cursor.u64()?),
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    let cancellation_requested = match cursor.byte()? {
        0 => false,
        1 => true,
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    let dispatches = cursor.u64()?;
    let checkpoint = match cursor.byte()? {
        0 => None,
        1 => {
            let sequence = cursor.u64()?;
            let completed = cursor.u32()?;
            let length =
                usize::try_from(cursor.u32()?).map_err(|_| MaintenanceFailure::InvalidInput)?;
            let progress = cursor.take_exact(length)?.to_vec();
            Some(MaintenanceCheckpoint::new(sequence, completed, progress)?)
        },
        _ => return Err(MaintenanceFailure::InvalidInput),
    };
    if !cursor.is_finished() {
        return Err(MaintenanceFailure::InvalidInput);
    }
    Ok(TaskState {
        task,
        phase,
        submitted_at,
        checkpoint,
        pause_until,
        cancellation_requested,
        dispatches,
    })
}

fn decode_objects(
    cursor: &mut RecordCursor<'_>,
) -> Result<Vec<MaintenanceObjectId>, MaintenanceFailure> {
    let count = usize::from(cursor.byte()?);
    if count > MAX_TASK_OBJECTS {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    for _ in 0..count {
        values.push(MaintenanceObjectId::new(cursor.array_32()?)?);
    }
    Ok(values)
}

fn encode_scope(bytes: &mut Vec<u8>, scope: MaintenanceScope) {
    match scope {
        MaintenanceScope::System => bytes.push(0),
        MaintenanceScope::Tenant {
            tenant,
            signal,
            shard,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&tenant.to_bytes());
            bytes.push(match signal {
                None => 0,
                Some(SignalKind::Logs) => 1,
                Some(SignalKind::Traces) => 2,
            });
            push_u32(bytes, shard.map_or(0, VirtualShardId::value));
        },
    }
}

fn decode_scope(cursor: &mut RecordCursor<'_>) -> Result<MaintenanceScope, MaintenanceFailure> {
    match cursor.byte()? {
        0 => Ok(MaintenanceScope::System),
        1 => {
            let tenant = TenantId::from_bytes(cursor.array_16()?)
                .map_err(|_| MaintenanceFailure::InvalidInput)?;
            let signal = match cursor.byte()? {
                0 => None,
                1 => Some(SignalKind::Logs),
                2 => Some(SignalKind::Traces),
                _ => return Err(MaintenanceFailure::InvalidInput),
            };
            let shard = match cursor.u32()? {
                0 => None,
                value => {
                    Some(VirtualShardId::new(value).map_err(|_| MaintenanceFailure::InvalidInput)?)
                },
            };
            if signal.is_some() != shard.is_some() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            Ok(MaintenanceScope::Tenant {
                tenant,
                signal,
                shard,
            })
        },
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}

fn class_code(class: MaintenanceTaskClass) -> u8 {
    class as u8
}
fn class_from_code(code: u8) -> Result<MaintenanceTaskClass, MaintenanceFailure> {
    const CLASSES: [MaintenanceTaskClass; 22] = [
        MaintenanceTaskClass::ActiveSegmentRoll,
        MaintenanceTaskClass::Compaction,
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceTaskClass::RetentionReclamation,
        MaintenanceTaskClass::CatalogReclamation,
        MaintenanceTaskClass::OrphanReclamation,
        MaintenanceTaskClass::IntegrityScrub,
        MaintenanceTaskClass::QuarantineFollowUp,
        MaintenanceTaskClass::SchemaStatistics,
        MaintenanceTaskClass::SchemaPromotion,
        MaintenanceTaskClass::SchemaDemotion,
        MaintenanceTaskClass::GovernanceAuditCheckpoint,
        MaintenanceTaskClass::KeyRewrap,
        MaintenanceTaskClass::EnvelopeVerification,
        MaintenanceTaskClass::Migration,
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceTaskClass::RepositoryCleanup,
        MaintenanceTaskClass::BackupSnapshot,
        MaintenanceTaskClass::DurableExport,
        MaintenanceTaskClass::SnapshotLeaseExpiry,
        MaintenanceTaskClass::CompletedOperationExpiry,
        MaintenanceTaskClass::TenantPurge,
    ];
    CLASSES
        .get(usize::from(code))
        .copied()
        .ok_or(MaintenanceFailure::InvalidInput)
}
fn trigger_code(trigger: MaintenanceTrigger) -> u8 {
    match trigger {
        MaintenanceTrigger::Event => 0,
        MaintenanceTrigger::Scheduled => 1,
        MaintenanceTrigger::AgeDerived => 2,
    }
}
fn trigger_from_code(code: u8) -> Result<MaintenanceTrigger, MaintenanceFailure> {
    match code {
        0 => Ok(MaintenanceTrigger::Event),
        1 => Ok(MaintenanceTrigger::Scheduled),
        2 => Ok(MaintenanceTrigger::AgeDerived),
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}
fn priority_code(priority: MaintenancePriority) -> u8 {
    match priority {
        MaintenancePriority::Ordinary => 0,
        MaintenancePriority::Required => 1,
        MaintenancePriority::Urgent => 2,
    }
}
fn priority_from_code(code: u8) -> Result<MaintenancePriority, MaintenanceFailure> {
    match code {
        0 => Ok(MaintenancePriority::Ordinary),
        1 => Ok(MaintenancePriority::Required),
        2 => Ok(MaintenancePriority::Urgent),
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}
fn phase_code(phase: MaintenanceTaskPhase) -> u8 {
    match phase {
        MaintenanceTaskPhase::Queued => 0,
        MaintenanceTaskPhase::Running => 1,
        MaintenanceTaskPhase::Deferred => 2,
        MaintenanceTaskPhase::Cancelled => 3,
        MaintenanceTaskPhase::Succeeded => 4,
        MaintenanceTaskPhase::Failed => 5,
    }
}
fn phase_from_code(code: u8) -> Result<MaintenanceTaskPhase, MaintenanceFailure> {
    match code {
        0 => Ok(MaintenanceTaskPhase::Queued),
        1 => Ok(MaintenanceTaskPhase::Running),
        2 => Ok(MaintenanceTaskPhase::Deferred),
        3 => Ok(MaintenanceTaskPhase::Cancelled),
        4 => Ok(MaintenanceTaskPhase::Succeeded),
        5 => Ok(MaintenanceTaskPhase::Failed),
        _ => Err(MaintenanceFailure::InvalidInput),
    }
}
fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

struct RecordCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> RecordCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take_exact(&mut self, length: usize) -> Result<&'a [u8], MaintenanceFailure> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, MaintenanceFailure> {
        self.take_exact(1)?
            .first()
            .copied()
            .ok_or(MaintenanceFailure::InvalidInput)
    }
    fn array_16(&mut self) -> Result<[u8; 16], MaintenanceFailure> {
        self.take_exact(16)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)
    }
    fn array_32(&mut self) -> Result<[u8; 32], MaintenanceFailure> {
        self.take_exact(32)?
            .try_into()
            .map_err(|_| MaintenanceFailure::InvalidInput)
    }
    fn u64(&mut self) -> Result<u64, MaintenanceFailure> {
        Ok(u64::from_be_bytes(
            self.take_exact(8)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, MaintenanceFailure> {
        Ok(u32::from_be_bytes(
            self.take_exact(4)?
                .try_into()
                .map_err(|_| MaintenanceFailure::InvalidInput)?,
        ))
    }
    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

impl Default for MaintenanceCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(
        identity: u8,
        class: MaintenanceTaskClass,
        trigger: MaintenanceTrigger,
        priority: MaintenancePriority,
        inputs: Vec<MaintenanceObjectId>,
    ) -> MaintenanceTask {
        MaintenanceTask::with_contract(
            MaintenanceTaskId::new([identity; 16]).expect("stable task identity"),
            class,
            MaintenanceScope::system(),
            trigger,
            priority,
            MaintenancePreconditions::new(4, 9).expect("valid preconditions"),
            inputs,
            Vec::new(),
            ResourceAmounts::new([64, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .expect("bounded task")
    }

    #[test]
    fn retrying_a_stable_identity_attaches_to_the_original_task() {
        let coordinator = MaintenanceCoordinator::new();
        let identity = MaintenanceTaskId::new([7; 16]).expect("non-zero stable identity");
        let original = coordinator
            .submit(MaintenanceTask::new(
                identity,
                MaintenanceTaskClass::Compaction,
            ))
            .expect("initial task is accepted");
        let retry = coordinator
            .submit(MaintenanceTask::new(
                identity,
                MaintenanceTaskClass::Compaction,
            ))
            .expect("retry attaches to existing work");

        assert_eq!(original, retry);
        assert_eq!(retry.class(), MaintenanceTaskClass::Compaction);
    }

    #[test]
    fn submitted_work_is_visible_to_the_single_scheduler() {
        let coordinator = MaintenanceCoordinator::new();
        let task = MaintenanceTask::new(
            MaintenanceTaskId::new([8; 16]).expect("non-zero stable identity"),
            MaintenanceTaskClass::Compaction,
        );
        coordinator.submit(task.clone()).expect("task is accepted");

        assert_eq!(
            coordinator.start_next(0, false).expect("scheduler runs"),
            Some(task)
        );
    }

    #[test]
    fn conflicting_copy_on_write_work_waits_for_the_running_owner() {
        let coordinator = MaintenanceCoordinator::new();
        let input = MaintenanceObjectId::new([3; 32]).expect("object identity");
        let first = task(
            1,
            MaintenanceTaskClass::Compaction,
            MaintenanceTrigger::Event,
            MaintenancePriority::Ordinary,
            vec![input],
        );
        let second = task(
            2,
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceTrigger::Event,
            MaintenancePriority::Required,
            vec![input],
        );
        coordinator
            .submit_at(first.clone(), 1)
            .expect("first accepted");
        coordinator
            .submit_at(second.clone(), 2)
            .expect("second accepted");

        assert_eq!(
            coordinator.start_next(3, false).expect("first starts"),
            Some(second)
        );
        assert_eq!(
            coordinator.start_next(4, false).expect("conflict waits"),
            None
        );
        coordinator
            .complete(
                MaintenanceTaskId::new([2; 16]).expect("task identity"),
                true,
            )
            .expect("complete");
        assert_eq!(
            coordinator.start_next(5, false).expect("unblocked"),
            Some(first)
        );
    }

    #[test]
    fn uncertain_clock_pauses_only_age_derived_destruction() {
        let coordinator = MaintenanceCoordinator::new();
        let retention = task(
            4,
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceTrigger::AgeDerived,
            MaintenancePriority::Required,
            Vec::new(),
        );
        let compaction = task(
            5,
            MaintenanceTaskClass::Compaction,
            MaintenanceTrigger::Event,
            MaintenancePriority::Ordinary,
            Vec::new(),
        );
        coordinator.submit(retention).expect("retention accepted");
        coordinator
            .submit(compaction.clone())
            .expect("safe compaction accepted");

        assert_eq!(
            coordinator.start_next(1, true).expect("scheduler runs"),
            Some(compaction)
        );
    }

    #[test]
    fn pause_expires_and_crash_requeues_checkpointed_work() {
        let coordinator = MaintenanceCoordinator::new();
        let task = task(
            6,
            MaintenanceTaskClass::Compaction,
            MaintenanceTrigger::Scheduled,
            MaintenancePriority::Ordinary,
            Vec::new(),
        );
        let identity = task.identity();
        coordinator.submit_at(task.clone(), 10).expect("accepted");
        coordinator
            .pause(identity, 9, 20, 10)
            .expect("optional work pauses");
        assert_eq!(
            coordinator.start_next(19, false).expect("still paused"),
            None
        );
        assert_eq!(
            coordinator.start_next(20, false).expect("expiry resumes"),
            Some(task)
        );
        coordinator
            .checkpoint(
                identity,
                MaintenanceCheckpoint::new(1, 0, vec![1]).expect("checkpoint"),
            )
            .expect("checkpoint retained");
        coordinator.recover_after_crash().expect("crash recovery");

        let status = coordinator.status(identity).expect("status");
        assert_eq!(status.phase(), MaintenanceTaskPhase::Queued);
        assert_eq!(
            status.checkpoint().map(MaintenanceCheckpoint::sequence),
            Some(1)
        );
    }

    #[test]
    fn pause_rejects_required_retention_work() {
        let coordinator = MaintenanceCoordinator::new();
        let task = task(
            7,
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceTrigger::Event,
            MaintenancePriority::Required,
            Vec::new(),
        );
        let identity = task.identity();
        coordinator.submit(task).expect("accepted");

        assert_eq!(
            coordinator.pause(identity, 9, 20, 10),
            Err(MaintenanceFailure::PreconditionFailed)
        );
    }

    #[test]
    fn task_and_checkpoint_bounds_reject_overflow_without_evicting_live_work() {
        let coordinator = MaintenanceCoordinator::new();
        for identity in 1..=u8::try_from(MAX_MAINTENANCE_TASKS).expect("task bound fits in u8") {
            coordinator
                .submit(task(
                    identity,
                    MaintenanceTaskClass::Compaction,
                    MaintenanceTrigger::Event,
                    MaintenancePriority::Ordinary,
                    Vec::new(),
                ))
                .expect("bounded task accepted");
        }

        assert!(matches!(
            coordinator.submit(task(
                129,
                MaintenanceTaskClass::Compaction,
                MaintenanceTrigger::Event,
                MaintenancePriority::Ordinary,
                Vec::new(),
            )),
            Err(MaintenanceFailure::CapacityExceeded)
        ));
        assert!(
            coordinator
                .status(MaintenanceTaskId::new([1; 16]).expect("identity"))
                .is_ok()
        );
        assert!(MaintenanceCheckpoint::new(1, 0, vec![0; MAX_CHECKPOINT_BYTES]).is_ok());
        assert_eq!(
            MaintenanceCheckpoint::new(1, 0, vec![0; MAX_CHECKPOINT_BYTES + 1]),
            Err(MaintenanceFailure::InvalidInput)
        );
    }

    #[test]
    fn cooperative_cancellation_prevents_terminal_success() {
        let coordinator = MaintenanceCoordinator::new();
        let task = task(
            8,
            MaintenanceTaskClass::Compaction,
            MaintenanceTrigger::Event,
            MaintenancePriority::Ordinary,
            Vec::new(),
        );
        let identity = task.identity();
        coordinator.submit(task.clone()).expect("accepted");
        assert_eq!(
            coordinator.start_next(1, false).expect("starts"),
            Some(task)
        );
        coordinator
            .cancel(identity)
            .expect("cancellation requested");
        assert!(
            coordinator
                .status(identity)
                .expect("status")
                .cancellation_requested()
        );
        coordinator
            .complete(identity, true)
            .expect("handler returns");

        assert_eq!(
            coordinator
                .status(identity)
                .expect("terminal status")
                .phase(),
            MaintenanceTaskPhase::Cancelled
        );
        assert_eq!(coordinator.start_next(2, false).expect("no rerun"), None);
    }

    #[test]
    fn a_repeated_urgent_scope_cannot_starve_an_unserved_tenant() {
        let coordinator = MaintenanceCoordinator::new();
        let first = MaintenanceTask::with_contract(
            MaintenanceTaskId::new([10; 16]).expect("identity"),
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceScope::tenant(TenantId::from_bytes([1; 16]).expect("tenant")),
            MaintenanceTrigger::Event,
            MaintenancePriority::Urgent,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .expect("task");
        let second = MaintenanceTask::with_contract(
            MaintenanceTaskId::new([11; 16]).expect("identity"),
            MaintenanceTaskClass::Compaction,
            MaintenanceScope::tenant(TenantId::from_bytes([2; 16]).expect("tenant")),
            MaintenanceTrigger::Event,
            MaintenancePriority::Ordinary,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .expect("task");
        let third = MaintenanceTask::with_contract(
            MaintenanceTaskId::new([12; 16]).expect("identity"),
            MaintenanceTaskClass::RetentionPublication,
            first.scope(),
            MaintenanceTrigger::Event,
            MaintenancePriority::Urgent,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .expect("task");
        coordinator.submit(first.clone()).expect("first");
        coordinator.submit(second.clone()).expect("second");
        coordinator.submit(third.clone()).expect("third");
        assert_eq!(
            coordinator.start_next(1, false).expect("start"),
            Some(first)
        );
        coordinator
            .complete(MaintenanceTaskId::new([10; 16]).expect("identity"), true)
            .expect("complete");
        assert_eq!(
            coordinator.start_next(2, false).expect("fair next"),
            Some(third)
        );
        coordinator
            .complete(MaintenanceTaskId::new([12; 16]).expect("identity"), true)
            .expect("complete");
        assert_eq!(
            coordinator.start_next(3, false).expect("bounded fair next"),
            Some(second)
        );
    }

    #[test]
    fn durable_checkpoint_restores_the_same_task_after_a_process_restart() {
        let coordinator = MaintenanceCoordinator::new();
        let task = task(
            9,
            MaintenanceTaskClass::Compaction,
            MaintenanceTrigger::Event,
            MaintenancePriority::Ordinary,
            Vec::new(),
        );
        let identity = task.identity();
        coordinator.submit(task).expect("accepted");
        coordinator.start_next(1, false).expect("start");
        coordinator
            .checkpoint(
                identity,
                MaintenanceCheckpoint::new(1, 0, vec![9, 8]).expect("checkpoint"),
            )
            .expect("record checkpoint");
        let records = coordinator.durable_records().expect("durable records");

        let restored = MaintenanceCoordinator::restore(records).expect("restore");
        assert_eq!(
            restored
                .status(identity)
                .expect("restored status")
                .checkpoint()
                .map(MaintenanceCheckpoint::opaque_progress),
            Some(&[9, 8][..])
        );
    }
}
