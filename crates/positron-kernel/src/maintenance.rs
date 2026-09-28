//! Bounded coordination of Storage Kernel background work.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::{
    CatalogObject, DiskPressureState, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts,
    ResourceDimension, ResourceReservation, StorageKernelResourceAuthority, WorkClaim, WorkKind,
};

mod record;

use record::{decode_record, encode_record};

const MAX_MAINTENANCE_TASKS: usize = 128;
const MAX_TASK_OBJECTS: usize = 16;
const MAX_CHECKPOINT_BYTES: usize = 4_096;
const MAX_LOWER_CLASS_QUEUE_DELAY: u64 = 60;
static NEXT_COORDINATOR_ID: AtomicU64 = AtomicU64::new(1);

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

    const fn priority(
        self,
        trigger: MaintenanceTrigger,
        emergency_compaction: bool,
    ) -> MaintenancePriority {
        match self {
            Self::ActiveSegmentRoll | Self::GovernanceAuditCheckpoint => {
                MaintenancePriority::Durability
            },
            Self::RetentionPublication
            | Self::RetentionReclamation
            | Self::CatalogReclamation
            | Self::OrphanReclamation
            | Self::IntegrityScrub
            | Self::QuarantineFollowUp
            | Self::KeyRewrap
            | Self::EnvelopeVerification
            | Self::Migration
            | Self::SnapshotLeaseExpiry
            | Self::CompletedOperationExpiry
            | Self::TenantPurge => MaintenancePriority::Urgent,
            Self::SchemaStatistics | Self::RepositoryCleanup => MaintenancePriority::Required,
            Self::Compaction => match trigger {
                MaintenanceTrigger::Event if emergency_compaction => MaintenancePriority::Urgent,
                MaintenanceTrigger::Event => MaintenancePriority::Required,
                MaintenanceTrigger::Scheduled | MaintenanceTrigger::AgeDerived => {
                    MaintenancePriority::Ordinary
                },
            },

            Self::SchemaPromotion
            | Self::SchemaDemotion
            | Self::RepositoryVerification
            | Self::BackupSnapshot
            | Self::DurableExport => MaintenancePriority::Ordinary,
        }
    }

    const fn is_window_deferrable(self, emergency_compaction: bool) -> bool {
        self.deferrable() && (!matches!(self, Self::Compaction) || !emergency_compaction)
    }
}

/// The bounded task scope used for fairness and conflicts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenanceScope {
    System,
    Tenant(TenantId),
    Segment {
        tenant: TenantId,
        signal: SignalKind,
        shard: VirtualShardId,
    },
}

impl MaintenanceScope {
    #[must_use]
    pub const fn system() -> Self {
        Self::System
    }

    #[must_use]
    pub const fn tenant(tenant: TenantId) -> Self {
        Self::Tenant(tenant)
    }

    #[must_use]
    pub const fn segment(tenant: TenantId, signal: SignalKind, shard: VirtualShardId) -> Self {
        Self::Segment {
            tenant,
            signal,
            shard,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> Option<TenantId> {
        match self {
            Self::System => None,
            Self::Tenant(tenant) | Self::Segment { tenant, .. } => Some(tenant),
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

/// A coordinator-derived scheduling class. Callers cannot promote arbitrary work.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MaintenancePriority {
    Ordinary,
    Required,
    Urgent,
    Durability,
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
    emergency_compaction: bool,
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
            emergency_compaction: false,
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
            emergency_compaction: false,
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
        self.class.priority(self.trigger, self.emergency_compaction)
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
    coordinator_id: u64,
}

#[derive(Clone)]
struct CoordinatorState {
    tasks: BTreeMap<MaintenanceTaskId, TaskState>,
    window: Option<MaintenanceWindow>,
    fairness: BTreeMap<(MaintenancePriority, MaintenanceScope), u64>,
    next_terminal_order: u64,
}

#[derive(Clone)]
struct MaintenanceWindow {
    deferred: BTreeSet<MaintenanceTaskClass>,
    until: u64,
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
    terminal_order: Option<u64>,
    active_dispatch: Option<MaintenanceDispatch>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaintenanceDispatch {
    coordinator_id: u64,
    identity: MaintenanceTaskId,
    attempt: u64,
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
    dispatch: MaintenanceDispatch,
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

    fn checkpoint_dispatch(
        &self,
        coordinator: &MaintenanceCoordinator,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        if self.dispatch.coordinator_id != coordinator.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get_mut(&self.dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(self.dispatch)
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

    pub fn checkpoint(
        &self,
        coordinator: &MaintenanceCoordinator,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        self.checkpoint_dispatch(coordinator, checkpoint)
    }

    fn complete_dispatch(
        &self,
        coordinator: &MaintenanceCoordinator,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        if self.dispatch.coordinator_id != coordinator.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        {
            let task = state
                .tasks
                .get_mut(&self.dispatch.identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if task.phase != MaintenanceTaskPhase::Running
                || task.active_dispatch != Some(self.dispatch)
            {
                return Err(MaintenanceFailure::InvalidTransition);
            }
            task.phase = if task.cancellation_requested {
                MaintenanceTaskPhase::Cancelled
            } else if succeeded {
                MaintenanceTaskPhase::Succeeded
            } else {
                MaintenanceTaskPhase::Failed
            };
            task.active_dispatch = None;
        }
        assign_terminal_order(&mut state, self.dispatch.identity)
    }

    pub fn complete(
        self,
        coordinator: &MaintenanceCoordinator,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        self.complete_dispatch(coordinator, succeeded)
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
                window: None,
                fairness: BTreeMap::new(),
                next_terminal_order: 1,
            }),
            coordinator_id: NEXT_COORDINATOR_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Attaches a retry with the same stable identity to its existing work.
    pub fn submit(&self, task: MaintenanceTask) -> Result<MaintenanceTask, MaintenanceFailure> {
        self.submit_at(task, 0)
    }

    /// Marks a compaction task as emergency work only after the sole Resource
    /// Governor has observed hard disk pressure. External callers cannot turn
    /// an ordinary event into Recovery Reserve work by selecting a priority.
    pub fn submit_emergency_compaction(
        &self,
        authority: &StorageKernelResourceAuthority,
        mut task: MaintenanceTask,
    ) -> Result<MaintenanceTask, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::Compaction
            || task.trigger != MaintenanceTrigger::Event
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let pressure = authority
            .governor()
            .inspect()
            .map_err(|_| MaintenanceFailure::ResourceAdmissionRefused)?
            .disk_pressure();
        if pressure != DiskPressureState::HardPressure {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        task.emergency_compaction = true;
        self.submit(task)
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
        if state.tasks.len() >= MAX_MAINTENANCE_TASKS && !reclaim_terminal_slot(&mut state)? {
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
                terminal_order: None,
                active_dispatch: None,
            },
        );
        Ok(task)
    }

    /// Defers only declared optional work for a finite Lifecycle Clock interval.
    /// Required work and event-driven emergency compaction stay schedulable.
    pub fn set_window(
        &self,
        deferred: impl IntoIterator<Item = MaintenanceTaskClass>,
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
        let mut classes = BTreeSet::new();
        for class in deferred {
            if !class.deferrable() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            classes.insert(class);
        }
        state.window = Some(MaintenanceWindow {
            deferred: classes,
            until,
        });
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
        let terminal = {
            let task = state
                .tasks
                .get_mut(&identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if retains_until_completion(&task.task) {
                return Err(MaintenanceFailure::PreconditionFailed);
            }
            match task.phase {
                MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Deferred => {
                    task.phase = MaintenanceTaskPhase::Cancelled;
                    true
                },
                MaintenanceTaskPhase::Running => {
                    task.cancellation_requested = true;
                    false
                },
                MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed => false,
            }
        };
        if terminal {
            assign_terminal_order(&mut state, identity)?;
        }
        Ok(())
    }

    /// Test and fuzz-only scheduling without a live Resource Governor. Product
    /// dispatches use `start_next_with_reservation` so admission precedes the
    /// Running transition.
    #[cfg(any(test, fuzzing))]
    fn start_next(
        &self,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceTask>, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let Some(identity) = eligible_task_ids(&mut state, now, clock_uncertain)?
            .first()
            .copied()
        else {
            return Ok(None);
        };
        let task = state
            .tasks
            .get(&identity)
            .map(|stored| stored.task.clone())
            .ok_or(MaintenanceFailure::UnknownTask)?;
        dispatch_task(&mut state, self.coordinator_id, identity, now)?;
        Ok(Some(task))
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
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let candidates = eligible_task_ids(&mut state, now, clock_uncertain)?;
        if candidates.is_empty() {
            return Ok(None);
        }
        for identity in candidates {
            let task = state
                .tasks
                .get(&identity)
                .map(|stored| stored.task.clone())
                .ok_or(MaintenanceFailure::UnknownTask)?;
            let reservation = match reserve_task(authority, &task) {
                Ok(reservation) => reservation,
                Err(()) => continue,
            };
            let dispatch = dispatch_task(&mut state, self.coordinator_id, identity, now)?;
            return Ok(Some(MaintenanceExecution {
                task,
                reservation,
                dispatch,
            }));
        }
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    }

    #[cfg(test)]
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

    #[cfg(test)]
    pub fn complete(
        &self,
        identity: MaintenanceTaskId,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        {
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
        }
        assign_terminal_order(&mut state, identity)?;
        Ok(())
    }

    /// Crash recovery releases ephemeral reservations and makes any nonterminal
    /// checkpointed task eligible to resume through its same stable identity.
    pub fn recover_after_crash(&self) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut terminal = Vec::new();
        for (identity, task) in &mut state.tasks {
            if task.phase == MaintenanceTaskPhase::Running {
                task.active_dispatch = None;
                task.phase = if task.cancellation_requested {
                    MaintenanceTaskPhase::Cancelled
                } else {
                    MaintenanceTaskPhase::Queued
                };
                if task.phase == MaintenanceTaskPhase::Cancelled {
                    terminal.push(*identity);
                }
            }
        }
        for identity in terminal {
            assign_terminal_order(&mut state, identity)?;
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
                state.phase = if state.cancellation_requested {
                    MaintenanceTaskPhase::Cancelled
                } else {
                    MaintenanceTaskPhase::Queued
                };
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

fn eligible_task_ids(
    state: &mut CoordinatorState,
    now: u64,
    clock_uncertain: bool,
) -> Result<Vec<MaintenanceTaskId>, MaintenanceFailure> {
    for task in state.tasks.values_mut() {
        if task.phase == MaintenanceTaskPhase::Deferred
            && task.pause_until.is_some_and(|until| until <= now)
        {
            task.phase = MaintenanceTaskPhase::Queued;
            task.pause_until = None;
        }
    }
    if state
        .window
        .as_ref()
        .is_some_and(|window| window.until <= now)
    {
        state.window = None;
    }
    let mut running = Vec::new();
    running
        .try_reserve_exact(state.tasks.len())
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    for task in state.tasks.values() {
        if task.phase == MaintenanceTaskPhase::Running {
            running.push(task.task.clone());
        }
    }
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(state.tasks.len())
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    for (identity, task) in &state.tasks {
        let clock_blocks = clock_uncertain
            && task.task.class.destructive()
            && matches!(
                task.task.trigger,
                MaintenanceTrigger::AgeDerived | MaintenanceTrigger::Scheduled
            );
        let window_blocks = state.window.as_ref().is_some_and(|window| {
            window.deferred.contains(&task.task.class)
                && task
                    .task
                    .class
                    .is_window_deferrable(task.task.emergency_compaction)
        });
        let conflicts = running
            .iter()
            .any(|active| tasks_conflict(&task.task, active));
        if task.phase == MaintenanceTaskPhase::Queued
            && !clock_blocks
            && !window_blocks
            && !conflicts
        {
            candidates.push(*identity);
        }
    }
    candidates.sort_unstable_by(|left, right| {
        match (state.tasks.get(left), state.tasks.get(right)) {
            (Some(left), Some(right)) => scheduling_order(left, right, &state.fairness, now),
            _ => left.cmp(right),
        }
    });
    Ok(candidates)
}

fn dispatch_task(
    state: &mut CoordinatorState,
    coordinator_id: u64,
    identity: MaintenanceTaskId,
    now: u64,
) -> Result<MaintenanceDispatch, MaintenanceFailure> {
    let (dispatch, fairness_key, next_fairness) = {
        let task = state
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Queued {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let attempt = task
            .dispatches
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let fairness_key = (scheduling_priority(task, now), task.task.scope);
        let next_fairness = state
            .fairness
            .get(&fairness_key)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        (
            MaintenanceDispatch {
                coordinator_id,
                identity,
                attempt,
            },
            fairness_key,
            next_fairness,
        )
    };
    let task = state
        .tasks
        .get_mut(&identity)
        .ok_or(MaintenanceFailure::UnknownTask)?;
    task.phase = MaintenanceTaskPhase::Running;
    task.dispatches = dispatch.attempt;
    task.active_dispatch = Some(dispatch);
    state.fairness.insert(fairness_key, next_fairness);
    Ok(dispatch)
}

fn scheduling_priority(task: &TaskState, now: u64) -> MaintenancePriority {
    match task.task.priority() {
        MaintenancePriority::Durability => MaintenancePriority::Durability,
        MaintenancePriority::Urgent => MaintenancePriority::Urgent,
        _priority if now.saturating_sub(task.submitted_at) >= MAX_LOWER_CLASS_QUEUE_DELAY => {
            MaintenancePriority::Urgent
        },
        priority => priority,
    }
}

fn reserve_task<'authority>(
    authority: &'authority StorageKernelResourceAuthority,
    task: &MaintenanceTask,
) -> Result<MaintenanceReservation<'authority>, ()> {
    let recovery_kind = recovery_kind(task);
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

fn recovery_kind(task: &MaintenanceTask) -> Option<RecoveryWorkKind> {
    match task.class {
        MaintenanceTaskClass::ActiveSegmentRoll
        | MaintenanceTaskClass::GovernanceAuditCheckpoint => {
            Some(RecoveryWorkKind::DurabilityCompletion)
        },
        MaintenanceTaskClass::Compaction if task.emergency_compaction => {
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
    }
}

fn retains_until_completion(task: &MaintenanceTask) -> bool {
    matches!(
        recovery_kind(task),
        Some(RecoveryWorkKind::DurabilityCompletion)
    )
}

fn assign_terminal_order(
    state: &mut CoordinatorState,
    identity: MaintenanceTaskId,
) -> Result<(), MaintenanceFailure> {
    let order = state.next_terminal_order;
    state.next_terminal_order = state
        .next_terminal_order
        .checked_add(1)
        .ok_or(MaintenanceFailure::CapacityExceeded)?;
    let task = state
        .tasks
        .get_mut(&identity)
        .ok_or(MaintenanceFailure::UnknownTask)?;
    task.terminal_order = Some(order);
    Ok(())
}

fn reclaim_terminal_slot(state: &mut CoordinatorState) -> Result<bool, MaintenanceFailure> {
    let candidate = state
        .tasks
        .iter()
        .filter(|(_, task)| {
            matches!(
                task.phase,
                MaintenanceTaskPhase::Cancelled
                    | MaintenanceTaskPhase::Succeeded
                    | MaintenanceTaskPhase::Failed
            )
        })
        .min_by_key(|(identity, task)| {
            (
                task.terminal_order.unwrap_or(u64::MAX),
                task.submitted_at,
                **identity,
            )
        })
        .map(|(identity, _)| *identity);
    let Some(identity) = candidate else {
        return Ok(false);
    };
    let removed = state
        .tasks
        .remove(&identity)
        .ok_or(MaintenanceFailure::UnknownTask)?;
    if !state
        .tasks
        .values()
        .any(|task| task.task.scope == removed.task.scope)
    {
        state
            .fairness
            .retain(|(_, scope), _| *scope != removed.task.scope);
    }
    Ok(true)
}

fn tasks_conflict(left: &MaintenanceTask, right: &MaintenanceTask) -> bool {
    if !scopes_overlap(left.scope, right.scope) {
        return false;
    }
    left.inputs.iter().any(|object| {
        right.inputs.binary_search(object).is_ok() || right.outputs.binary_search(object).is_ok()
    }) || left.outputs.iter().any(|object| {
        right.inputs.binary_search(object).is_ok() || right.outputs.binary_search(object).is_ok()
    }) || matches!(left.class, MaintenanceTaskClass::TenantPurge)
        || matches!(right.class, MaintenanceTaskClass::TenantPurge)
}

fn scopes_overlap(left: MaintenanceScope, right: MaintenanceScope) -> bool {
    match (left, right) {
        (MaintenanceScope::System, MaintenanceScope::System) => true,
        (MaintenanceScope::Tenant(left), MaintenanceScope::Tenant(right)) => left == right,
        (MaintenanceScope::Tenant(left), MaintenanceScope::Segment { tenant, .. })
        | (MaintenanceScope::Segment { tenant, .. }, MaintenanceScope::Tenant(left)) => {
            left == tenant
        },
        (
            MaintenanceScope::Segment {
                tenant: left_tenant,
                signal: left_signal,
                shard: left_shard,
            },
            MaintenanceScope::Segment {
                tenant: right_tenant,
                signal: right_signal,
                shard: right_shard,
            },
        ) => {
            left_tenant == right_tenant && left_signal == right_signal && left_shard == right_shard
        },
        (MaintenanceScope::System, _) | (_, MaintenanceScope::System) => false,
    }
}

fn scheduling_order(
    left: &TaskState,
    right: &TaskState,
    fairness: &BTreeMap<(MaintenancePriority, MaintenanceScope), u64>,
    now: u64,
) -> std::cmp::Ordering {
    let left_priority = scheduling_priority(left, now);
    let right_priority = scheduling_priority(right, now);
    let left_dispatches = fairness
        .get(&(left_priority, left.task.scope))
        .copied()
        .unwrap_or(0);
    let right_dispatches = fairness
        .get(&(right_priority, right.task.scope))
        .copied()
        .unwrap_or(0);
    right_priority
        .cmp(&left_priority)
        .then_with(|| left_dispatches.cmp(&right_dispatches))
        .then_with(|| left.dispatches.cmp(&right.dispatches))
        .then_with(|| left.submitted_at.cmp(&right.submitted_at))
        .then_with(|| left.task.identity.cmp(&right.task.identity))
}

impl Default for MaintenanceCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "maintenance/tests.rs"]
mod tests;
