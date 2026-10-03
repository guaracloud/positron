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

mod compaction;
mod persistence;
mod record;

pub use compaction::CompactionBinding;
pub(crate) use compaction::{compaction_task_record_bytes, compaction_task_record_working_bytes};

pub(crate) use persistence::{
    SnapshotLeaseExpiryTaskReplacement, retention_publication_record_bytes_bound,
};
use record::{decode_record, encode_record};

pub(crate) fn durable_task_record_identity(
    bytes: &[u8],
) -> Result<Option<MaintenanceTaskId>, MaintenanceFailure> {
    record::record_identity(bytes)
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rewrite_durable_task_record_dispatches_for_test(
    bytes: &[u8],
    dispatches: u64,
) -> Result<Vec<u8>, MaintenanceFailure> {
    let mut state = record::decode_record(bytes)?;
    state.dispatches = dispatches;
    Ok(record::encode_record(&state)?.as_bytes().to_vec())
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rewrite_durable_task_record_not_before_for_test(
    bytes: &[u8],
    not_before: u64,
) -> Result<Vec<u8>, MaintenanceFailure> {
    let mut state = record::decode_record(bytes)?;
    state.task.not_before = not_before;
    Ok(record::encode_record(&state)?.as_bytes().to_vec())
}

#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rewrite_durable_task_record_trigger_for_test(
    bytes: &[u8],
    trigger: MaintenanceTrigger,
) -> Result<Vec<u8>, MaintenanceFailure> {
    let mut state = record::decode_record(bytes)?;
    state.task.trigger = trigger;
    Ok(record::encode_record(&state)?.as_bytes().to_vec())
}

const MAX_MAINTENANCE_TASKS: usize = 128;
pub(crate) const MAX_TASK_OBJECTS: usize = 16;
pub(crate) const MAX_CHECKPOINT_BYTES: usize = 4_096;
const RETENTION_PUBLICATION_FRONTIER_MAGIC: &[u8; 8] = b"RTPFR001";
const GOVERNANCE_AUDIT_CHECKPOINT_BINDING_MAGIC: &[u8; 8] = b"GACPB001";
const GOVERNANCE_AUDIT_CHECKPOINT_BINDING_BYTES: usize = 8 + 8 + 32 + 32;

pub(crate) fn retention_publication_frontier_checkpoint(
    frontier: crate::IngestTime,
) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(RETENTION_PUBLICATION_FRONTIER_MAGIC.len() + 8)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    bytes.extend_from_slice(RETENTION_PUBLICATION_FRONTIER_MAGIC);
    bytes.extend_from_slice(&frontier.instant().value().to_be_bytes());
    MaintenanceCheckpoint::new(1, 0, bytes)
}

pub(crate) fn retention_publication_frontier(
    checkpoint: Option<&MaintenanceCheckpoint>,
) -> Result<crate::IngestTime, MaintenanceFailure> {
    let checkpoint = checkpoint.ok_or(MaintenanceFailure::InvalidInput)?;
    let bytes = checkpoint.opaque_progress();
    if checkpoint.sequence() != 1
        || checkpoint.completed_inputs() != 0
        || bytes.len() != RETENTION_PUBLICATION_FRONTIER_MAGIC.len() + 8
        || !bytes.starts_with(RETENTION_PUBLICATION_FRONTIER_MAGIC)
    {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let instant = bytes
        .get(RETENTION_PUBLICATION_FRONTIER_MAGIC.len()..)
        .ok_or(MaintenanceFailure::InvalidInput)?
        .try_into()
        .map_err(|_| MaintenanceFailure::InvalidInput)?;
    Ok(crate::IngestTime::from_authenticated_durable(
        positron_domain::time::UnixNanoseconds::new(i64::from_be_bytes(instant)),
    ))
}

/// The immutable frontier and integrity-key identity a governance checkpoint
/// task must sign. Keeping this in the durable task checkpoint prevents a
/// delayed worker from silently advancing a caller's requested frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernanceAuditCheckpointBinding {
    position: u64,
    record_hash: [u8; 32],
    integrity_key_fingerprint: [u8; 32],
}

impl GovernanceAuditCheckpointBinding {
    pub fn new(
        position: u64,
        record_hash: [u8; 32],
        integrity_key_fingerprint: [u8; 32],
    ) -> Result<Self, MaintenanceFailure> {
        if position == 0
            || record_hash.iter().all(|byte| *byte == 0)
            || integrity_key_fingerprint.iter().all(|byte| *byte == 0)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        Ok(Self {
            position,
            record_hash,
            integrity_key_fingerprint,
        })
    }

    #[must_use]
    pub const fn position(self) -> u64 {
        self.position
    }

    #[must_use]
    pub const fn record_hash(self) -> [u8; 32] {
        self.record_hash
    }

    #[must_use]
    pub const fn integrity_key_fingerprint(self) -> [u8; 32] {
        self.integrity_key_fingerprint
    }

    pub fn checkpoint(self) -> Result<MaintenanceCheckpoint, MaintenanceFailure> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(GOVERNANCE_AUDIT_CHECKPOINT_BINDING_BYTES)
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        bytes.extend_from_slice(GOVERNANCE_AUDIT_CHECKPOINT_BINDING_MAGIC);
        bytes.extend_from_slice(&self.position.to_be_bytes());
        bytes.extend_from_slice(&self.record_hash);
        bytes.extend_from_slice(&self.integrity_key_fingerprint);
        MaintenanceCheckpoint::new(1, 0, bytes)
    }

    pub fn from_checkpoint(
        checkpoint: Option<&MaintenanceCheckpoint>,
    ) -> Result<Self, MaintenanceFailure> {
        let checkpoint = checkpoint.ok_or(MaintenanceFailure::InvalidInput)?;
        let bytes = checkpoint.opaque_progress();
        if checkpoint.sequence() != 1
            || checkpoint.completed_inputs() != 0
            || bytes.len() != GOVERNANCE_AUDIT_CHECKPOINT_BINDING_BYTES
            || !bytes.starts_with(GOVERNANCE_AUDIT_CHECKPOINT_BINDING_MAGIC)
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let position = bytes
            .get(8..16)
            .and_then(|value| value.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let record_hash = bytes
            .get(16..48)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::InvalidInput)?;
        let integrity_key_fingerprint = bytes
            .get(48..80)
            .and_then(|value| value.try_into().ok())
            .ok_or(MaintenanceFailure::InvalidInput)?;
        Self::new(position, record_hash, integrity_key_fingerprint)
    }
}
const MAX_LOWER_CLASS_QUEUE_DELAY: u64 = 60;
static NEXT_COORDINATOR_ID: AtomicU64 = AtomicU64::new(1);

mod model;

pub use model::*;

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
    pending_submissions: BTreeSet<MaintenanceTaskId>,
    pending_terminal_reclamations: BTreeSet<MaintenanceTaskId>,
    pending_task_transitions: BTreeSet<MaintenanceTaskId>,
    window: Option<MaintenanceWindow>,
    clock_uncertain_durable_eligibility: BTreeSet<MaintenanceTaskId>,
    fairness: BTreeMap<(MaintenancePriority, MaintenanceScope), u64>,
    next_terminal_order: u64,
}

fn require_unreserved_task_transition(
    state: &CoordinatorState,
    identity: MaintenanceTaskId,
) -> Result<(), MaintenanceFailure> {
    if state.pending_task_transitions.contains(&identity) {
        return Err(MaintenanceFailure::PreconditionFailed);
    }
    Ok(())
}

#[derive(Clone)]
struct MaintenanceWindow {
    deferred: BTreeSet<MaintenanceTaskClass>,
    until: u64,
}

#[derive(Clone, Eq, PartialEq)]
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

fn validate_retention_publication_state(state: &TaskState) -> Result<(), MaintenanceFailure> {
    if state.task.class == MaintenanceTaskClass::RetentionPublication {
        let _ = retention_publication_frontier(state.checkpoint.as_ref())?;
    }
    if state.task.class == MaintenanceTaskClass::GovernanceAuditCheckpoint {
        let binding = GovernanceAuditCheckpointBinding::from_checkpoint(state.checkpoint.as_ref())?;
        if !matches!(state.task.scope, MaintenanceScope::System)
            || state.task.inputs.len() != 1
            || state.task.inputs[0].to_bytes() != binding.record_hash()
            || state.task.outputs.len() != 1
            || state.task.outputs[0].to_bytes() != binding.integrity_key_fingerprint()
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
    }
    Ok(())
}

fn validate_retention_reclamation_state(state: &TaskState) -> Result<(), MaintenanceFailure> {
    let task = &state.task;
    if task.class != MaintenanceTaskClass::RetentionReclamation {
        return Ok(());
    }
    let MaintenanceScope::Segment { .. } = task.scope else {
        return Err(MaintenanceFailure::InvalidInput);
    };
    let Some(first) = task.inputs.first() else {
        return Err(MaintenanceFailure::InvalidInput);
    };
    if !matches!(
        task.trigger,
        MaintenanceTrigger::Event | MaintenanceTrigger::AgeDerived
    ) || task.inputs.len() > 16
        || !task.outputs.is_empty()
        || task.not_before != 0
        || task.emergency_compaction
        || state.checkpoint.is_some()
        || state.pause_until.is_some()
        || task.inputs.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(MaintenanceFailure::InvalidInput);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&first.to_bytes()[..16]);
    bytes[0] ^= 0xa5;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    if task.identity != MaintenanceTaskId::new(bytes)? {
        return Err(MaintenanceFailure::InvalidInput);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MaintenanceDispatch {
    coordinator_id: u64,
    identity: MaintenanceTaskId,
    attempt: u64,
}

/// Immutable durable binding that ties a running Snapshot Lease expiry task to
/// the one lease record it may remove.
pub(crate) struct SnapshotLeaseExpiryBinding<'record> {
    identity: crate::SnapshotLeaseId,
    scope: MaintenanceScope,
    lease_object: crate::CatalogObjectId,
    predecessor_generation: u64,
    not_before: u64,
    durable_record: &'record [u8],
}

/// Immutable task records that the ledger must atomically replace when a
/// Retention Publication becomes visible. The coordinator owns the state
/// transition; the ledger owns the matching Catalog publication.
pub(crate) struct RetentionPublicationBinding<'task, 'record> {
    publication: &'task MaintenanceTask,
    reclamation: MaintenanceTask,
    durable_record: &'record [u8],
}

impl<'task, 'record> RetentionPublicationBinding<'task, 'record> {
    #[must_use]
    pub(crate) const fn new(
        publication: &'task MaintenanceTask,
        reclamation: MaintenanceTask,
        durable_record: &'record [u8],
    ) -> Self {
        Self {
            publication,
            reclamation,
            durable_record,
        }
    }
}

impl<'record> SnapshotLeaseExpiryBinding<'record> {
    #[must_use]
    pub(crate) const fn new(
        identity: crate::SnapshotLeaseId,
        scope: MaintenanceScope,
        lease_object: crate::CatalogObjectId,
        predecessor_generation: u64,
        not_before: u64,
        durable_record: &'record [u8],
    ) -> Self {
        Self {
            identity,
            scope,
            lease_object,
            predecessor_generation,
            not_before,
            durable_record,
        }
    }
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

    pub(crate) fn authorizes_ordinary_compaction(
        &self,
        governor: crate::ResourceGovernor<'_>,
        tenant: TenantId,
    ) -> bool {
        match self {
            Self::Ordinary(reservation) => {
                reservation.belongs_to(governor)
                    && reservation.authorizes_ordinary_compaction(tenant)
            },
            Self::Recovery(_) => false,
        }
    }
}

/// A task selected by the coordinator after its complete peak reservation was admitted.
pub struct MaintenanceExecution<'authority> {
    task: MaintenanceTask,
    checkpoint: Option<MaintenanceCheckpoint>,
    reservation: MaintenanceReservation<'authority>,
    dispatch: MaintenanceDispatch,
}

impl MaintenanceExecution<'_> {
    #[must_use]
    pub fn task(&self) -> &MaintenanceTask {
        &self.task
    }
    #[must_use]
    pub fn task_checkpoint(&self) -> Option<&MaintenanceCheckpoint> {
        self.checkpoint.as_ref()
    }
    #[must_use]
    pub fn reservation(&self) -> &MaintenanceReservation<'_> {
        &self.reservation
    }

    #[cfg(any(test, fuzzing))]
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
        require_unreserved_task_transition(&state, self.dispatch.identity)?;
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

    #[cfg(any(test, fuzzing))]
    pub fn checkpoint(
        &self,
        coordinator: &MaintenanceCoordinator,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        self.checkpoint_dispatch(coordinator, checkpoint)
    }

    #[cfg(any(test, fuzzing))]
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
        require_unreserved_task_transition(&state, self.dispatch.identity)?;
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

    #[cfg(any(test, fuzzing))]
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
                pending_submissions: BTreeSet::new(),
                pending_terminal_reclamations: BTreeSet::new(),
                pending_task_transitions: BTreeSet::new(),
                window: None,
                clock_uncertain_durable_eligibility: BTreeSet::new(),
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
        if state
            .tasks
            .len()
            .checked_add(state.pending_submissions.len())
            .ok_or(MaintenanceFailure::CapacityExceeded)?
            >= MAX_MAINTENANCE_TASKS
            && reclaim_terminal_slot(&mut state)?.is_none()
        {
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
    #[cfg(any(test, fuzzing))]
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
    #[cfg(any(test, fuzzing))]
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

    #[cfg(any(test, fuzzing))]
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
    #[cfg(any(test, fuzzing))]
    pub fn cancel(&self, identity: MaintenanceTaskId) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        require_unreserved_task_transition(&state, identity)?;
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
    #[cfg(any(test, fuzzing))]
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
                checkpoint: state
                    .tasks
                    .get(&identity)
                    .and_then(|stored| stored.checkpoint.clone()),
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
        require_unreserved_task_transition(&state, identity)?;
        let task = state
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || task.task.class == MaintenanceTaskClass::RetentionPublication
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
        require_unreserved_task_transition(&state, identity)?;
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
    #[cfg(any(test, fuzzing))]
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
        state.pending_submissions.clear();
        state.pending_terminal_reclamations.clear();
        state.pending_task_transitions.clear();
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

    /// Reports whether a nonterminal retention task already owns a segment
    /// scope. Runtime discovery uses this bounded coordinator view to avoid
    /// preparing a second descriptor while the durable first attempt or its
    /// Reclamation successor remains authoritative.
    pub fn has_nonterminal_retention_task_for_scope(
        &self,
        scope: MaintenanceScope,
    ) -> Result<bool, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        Ok(state.tasks.values().any(|task| {
            task.task.scope == scope
                && matches!(
                    task.task.class,
                    MaintenanceTaskClass::RetentionPublication
                        | MaintenanceTaskClass::RetentionReclamation
                )
                && !matches!(
                    task.phase,
                    MaintenanceTaskPhase::Cancelled
                        | MaintenanceTaskPhase::Succeeded
                        | MaintenanceTaskPhase::Failed
                )
        }))
    }

    pub fn restore(
        records: impl IntoIterator<Item = MaintenanceTaskRecord>,
    ) -> Result<Self, MaintenanceFailure> {
        let coordinator = Self::new();
        for record in records {
            let mut state = decode_record(record.as_bytes())?;
            validate_retention_publication_state(&state)?;
            validate_retention_reclamation_state(&state)?;
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

mod scheduling;

use scheduling::{
    assign_terminal_order, dispatch_task, eligible_task_ids, reclaim_terminal_slot, reserve_task,
    retains_until_completion,
};
#[cfg(test)]
use scheduling::{recovery_kind, scheduling_order};

impl Default for MaintenanceCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "maintenance/tests.rs"]
mod tests;
