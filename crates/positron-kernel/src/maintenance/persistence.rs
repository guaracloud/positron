//! Catalog-backed maintenance task records.
//!
//! The coordinator owns task state while the Catalog Writer remains the sole
//! durable publication authority. Each transition first replaces the one
//! task's record in a complete Catalog proposal, then makes the corresponding
//! in-memory transition visible. An acknowledgement-ambiguous commit is safe
//! to retry because the exact replacement record is content-addressed.

use std::collections::BTreeSet;

use super::*;
use crate::{Catalog, CatalogObject, CatalogProposal, TransactionId};

/// A not-yet-visible task record prepared by the coordinator for inclusion in
/// a caller-owned Catalog transaction. The ledger uses this only to couple a
/// newly created Snapshot Lease to its expiry work; it cannot inspect or
/// mutate coordinator state directly.
pub(crate) struct QueuedMaintenanceSubmission {
    state: TaskState,
    record: MaintenanceTaskRecord,
    reclaimed_terminal: Option<(MaintenanceTaskId, TaskState)>,
}

/// A terminal replacement for the exact expiry record attached to a released
/// Snapshot Lease. Like a queued submission, it stays opaque until the
/// caller-owned Catalog proposal has committed.
pub(crate) struct SnapshotLeaseExpiryCancellation {
    before: TaskState,
    after: TaskState,
    next_terminal_order: u64,
    record: MaintenanceTaskRecord,
}

impl SnapshotLeaseExpiryCancellation {
    #[must_use]
    pub(crate) const fn task_identity(&self) -> MaintenanceTaskId {
        self.before.task.identity
    }

    pub(crate) fn catalog_object(&self) -> Result<CatalogObject, MaintenanceFailure> {
        self.record.catalog_object()
    }

    pub(crate) fn install(
        self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if state.tasks.get(&self.before.task.identity) != Some(&self.before) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }
}

impl QueuedMaintenanceSubmission {
    pub(crate) fn catalog_object(&self) -> Result<CatalogObject, MaintenanceFailure> {
        self.record.catalog_object()
    }

    #[must_use]
    pub(crate) fn reclaimed_task_identity(&self) -> Option<MaintenanceTaskId> {
        self.reclaimed_terminal
            .as_ref()
            .map(|(identity, _)| *identity)
    }

    pub(crate) fn install(
        self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if !state
            .pending_submissions
            .contains(&self.state.task.identity)
            || state.tasks.contains_key(&self.state.task.identity)
            || self
                .reclaimed_terminal
                .as_ref()
                .is_some_and(|(identity, expected)| {
                    !state.pending_terminal_reclamations.contains(identity)
                        || state.tasks.get(identity) != Some(expected)
                })
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state.pending_submissions.remove(&self.state.task.identity);
        if let Some((identity, _)) = self.reclaimed_terminal {
            state.pending_terminal_reclamations.remove(&identity);
            super::scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
        }
        state.tasks.insert(self.state.task.identity, self.state);
        Ok(())
    }

    pub(crate) fn discard(self, coordinator: &MaintenanceCoordinator) {
        if let Ok(mut state) = coordinator.state.lock() {
            state.pending_submissions.remove(&self.state.task.identity);
            if let Some((identity, _)) = self.reclaimed_terminal {
                state.pending_terminal_reclamations.remove(&identity);
            }
        }
    }
}

impl MaintenanceCoordinator {
    pub(crate) fn install_snapshot_lease_expiry_cancellations(
        &self,
        cancellations: Vec<SnapshotLeaseExpiryCancellation>,
        submission: QueuedMaintenanceSubmission,
    ) -> Result<(), MaintenanceFailure> {
        let QueuedMaintenanceSubmission {
            state: submission_state,
            reclaimed_terminal,
            ..
        } = submission;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if !state
            .pending_submissions
            .contains(&submission_state.task.identity)
            || state.tasks.contains_key(&submission_state.task.identity)
            || reclaimed_terminal
                .as_ref()
                .is_some_and(|(identity, expected)| {
                    !state.pending_terminal_reclamations.contains(identity)
                        || state.tasks.get(identity) != Some(expected)
                })
            || cancellations.iter().any(|cancellation| {
                state.tasks.get(&cancellation.before.task.identity) != Some(&cancellation.before)
            })
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_submissions
            .remove(&submission_state.task.identity);
        if let Some((identity, _)) = reclaimed_terminal {
            state.pending_terminal_reclamations.remove(&identity);
            super::scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
        }
        for cancellation in cancellations {
            state
                .tasks
                .insert(cancellation.after.task.identity, cancellation.after);
            state.next_terminal_order = state
                .next_terminal_order
                .max(cancellation.next_terminal_order);
        }
        state
            .tasks
            .insert(submission_state.task.identity, submission_state);
        Ok(())
    }

    pub(crate) fn install_snapshot_lease_expiry_replacement(
        &self,
        cancellation: SnapshotLeaseExpiryCancellation,
        submission: QueuedMaintenanceSubmission,
    ) -> Result<(), MaintenanceFailure> {
        let QueuedMaintenanceSubmission {
            state: submission_state,
            reclaimed_terminal,
            ..
        } = submission;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if state.tasks.get(&cancellation.before.task.identity) != Some(&cancellation.before)
            || !state
                .pending_submissions
                .contains(&submission_state.task.identity)
            || state.tasks.contains_key(&submission_state.task.identity)
            || reclaimed_terminal
                .as_ref()
                .is_some_and(|(identity, expected)| {
                    !state.pending_terminal_reclamations.contains(identity)
                        || state.tasks.get(identity) != Some(expected)
                })
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_submissions
            .remove(&submission_state.task.identity);
        if let Some((identity, _)) = reclaimed_terminal {
            state.pending_terminal_reclamations.remove(&identity);
            super::scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
        }
        state
            .tasks
            .insert(cancellation.after.task.identity, cancellation.after);
        state
            .tasks
            .insert(submission_state.task.identity, submission_state);
        state.next_terminal_order = state
            .next_terminal_order
            .max(cancellation.next_terminal_order);
        Ok(())
    }

    pub(crate) fn prepare_snapshot_lease_expiry_cancellation(
        &self,
        identity: crate::SnapshotLeaseId,
        scope: MaintenanceScope,
        lease_object: crate::CatalogObjectId,
        predecessor_generation: u64,
        not_before: u64,
        durable_record: &[u8],
    ) -> Result<Option<SnapshotLeaseExpiryCancellation>, MaintenanceFailure> {
        let identity = MaintenanceTaskId::new(identity.to_bytes())?;
        let expected_input = MaintenanceObjectId::new(lease_object.to_bytes())?;
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::SnapshotLeaseExpiry
            || before.task.scope != scope
            || before.task.trigger != MaintenanceTrigger::Scheduled
            || before.task.preconditions.catalog_generation != predecessor_generation
            || before.task.preconditions.resource_generation != 1
            || before.task.inputs.as_slice() != [expected_input]
            || !before.task.outputs.is_empty()
            || before.task.not_before != not_before
            || encode_record(&before)?.as_bytes() != durable_record
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        if matches!(
            before.phase,
            MaintenanceTaskPhase::Cancelled
                | MaintenanceTaskPhase::Succeeded
                | MaintenanceTaskPhase::Failed
        ) {
            return Ok(None);
        }
        if before.phase != MaintenanceTaskPhase::Queued {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut next = state.clone();
        let after = next
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        after.phase = MaintenanceTaskPhase::Cancelled;
        after.cancellation_requested = false;
        assign_terminal_order(&mut next, identity)?;
        let after = next
            .tasks
            .get(&identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let record = encode_record(&after)?;
        Ok(Some(SnapshotLeaseExpiryCancellation {
            before,
            after,
            next_terminal_order: next.next_terminal_order,
            record,
        }))
    }

    /// Prepares the one expiry task that must become reachable in the same
    /// Catalog generation as its Snapshot Lease. It deliberately makes no
    /// in-memory state visible until the lease publisher reports that commit.
    pub(crate) fn prepare_snapshot_lease_expiry(
        &self,
        identity: crate::SnapshotLeaseId,
        scope: MaintenanceScope,
        lease_object: crate::CatalogObjectId,
        predecessor_generation: u64,
        not_before: u64,
    ) -> Result<QueuedMaintenanceSubmission, MaintenanceFailure> {
        let task = MaintenanceTask::with_contract_not_before(
            MaintenanceTaskId::new(identity.to_bytes())?,
            MaintenanceTaskClass::SnapshotLeaseExpiry,
            scope,
            MaintenanceTrigger::Scheduled,
            MaintenancePreconditions::new(predecessor_generation, 1)?,
            vec![MaintenanceObjectId::new(lease_object.to_bytes())?],
            Vec::new(),
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
            not_before,
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if state.tasks.contains_key(&task.identity) {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let occupied = state
            .tasks
            .len()
            .checked_add(state.pending_submissions.len())
            .and_then(|count| count.checked_sub(state.pending_terminal_reclamations.len()))
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let reclaimed_terminal = if occupied >= MAX_MAINTENANCE_TASKS {
            let mut prospective = state.clone();
            for identity in &state.pending_terminal_reclamations {
                prospective.tasks.remove(identity);
            }
            let identity = reclaim_terminal_slot(&mut prospective)?
                .ok_or(MaintenanceFailure::CapacityExceeded)?;
            let terminal = state
                .tasks
                .get(&identity)
                .cloned()
                .ok_or(MaintenanceFailure::UnknownTask)?;
            Some((identity, terminal))
        } else {
            None
        };
        state.pending_submissions.insert(task.identity);
        if let Some((identity, _)) = &reclaimed_terminal {
            state.pending_terminal_reclamations.insert(*identity);
        }
        drop(state);
        let state = TaskState {
            task,
            phase: MaintenanceTaskPhase::Queued,
            submitted_at: not_before,
            checkpoint: None,
            pause_until: None,
            cancellation_requested: false,
            dispatches: 0,
            terminal_order: None,
            active_dispatch: None,
        };
        let record = encode_record(&state)?;
        Ok(QueuedMaintenanceSubmission {
            state,
            record,
            reclaimed_terminal,
        })
    }
    /// Selects, reserves, and durably marks one task Running before handing its
    /// execution to a handler. A failed publication drops the fresh reservation
    /// and leaves the task queued for the same stable retry.
    pub fn start_next_with_reservation_and_persist<'authority>(
        &self,
        catalog: &Catalog<'_>,
        authority: &'authority StorageKernelResourceAuthority,
        now: u64,
        clock_uncertain: bool,
    ) -> Result<Option<MaintenanceExecution<'authority>>, MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut prospective = state.clone();
        let candidates = eligible_task_ids(&mut prospective, now, clock_uncertain)?;
        if candidates.is_empty() {
            return Ok(None);
        }
        for identity in candidates {
            let task = prospective
                .tasks
                .get(&identity)
                .map(|stored| stored.task.clone())
                .ok_or(MaintenanceFailure::UnknownTask)?;
            let reservation = match reserve_task(authority, &task) {
                Ok(reservation) => reservation,
                Err(()) => continue,
            };
            let dispatch = dispatch_task(&mut prospective, self.coordinator_id, identity, now)?;
            let updated = prospective
                .tasks
                .get(&identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if let Err(failure) = persist_task_state(catalog, updated, None) {
                drop(reservation);
                return Err(failure);
            }
            let updated = updated.clone();
            state.tasks.insert(identity, updated);
            state.fairness = prospective.fairness;
            return Ok(Some(MaintenanceExecution {
                task,
                reservation,
                dispatch,
            }));
        }
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    }

    /// Submits a task only after its queued state is durably reachable through
    /// the current Catalog generation. Retrying the same stable task identity
    /// attaches to the already published record.
    pub fn submit_and_persist(
        &self,
        catalog: &Catalog<'_>,
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

        let mut next = state.clone();
        let occupied = next
            .tasks
            .len()
            .checked_add(next.pending_submissions.len())
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let removed = if occupied >= MAX_MAINTENANCE_TASKS {
            Some(reclaim_terminal_slot(&mut next)?.ok_or(MaintenanceFailure::CapacityExceeded)?)
        } else {
            None
        };
        let task_state = TaskState {
            task: task.clone(),
            phase: MaintenanceTaskPhase::Queued,
            submitted_at: now,
            checkpoint: None,
            pause_until: None,
            cancellation_requested: false,
            dispatches: 0,
            terminal_order: None,
            active_dispatch: None,
        };
        persist_task_state(catalog, &task_state, removed)?;
        next.tasks.insert(task.identity, task_state);
        *state = next;
        Ok(task)
    }

    /// Publishes a finite pause before exposing it to the scheduler.
    pub fn pause_and_persist(
        &self,
        catalog: &Catalog<'_>,
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
        let mut next = state.clone();
        let task = next
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
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }

    /// Removes a durable pause before returning the task to the queue.
    pub fn resume_and_persist(
        &self,
        catalog: &Catalog<'_>,
        identity: MaintenanceTaskId,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let task = next
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Deferred {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Queued;
        task.pause_until = None;
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }

    /// Durably requests cancellation before it is visible to the handler or
    /// scheduler. A protected durability completion remains non-cancellable.
    pub fn cancel_and_persist(
        &self,
        catalog: &Catalog<'_>,
        identity: MaintenanceTaskId,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let terminal = {
            let task = next
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
            assign_terminal_order(&mut next, identity)?;
        }
        let task = next
            .tasks
            .get(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }

    /// Recovers the complete bounded task registry from authenticated Catalog
    /// objects. Running work never owns durable capacity after a process exit,
    /// so it is returned to its queued checkpoint before any handler resumes.
    pub fn restore_from_catalog(catalog: &Catalog<'_>) -> Result<Self, MaintenanceFailure> {
        let snapshot = catalog.pin().map_err(map_catalog_failure)?;
        let mut identities = BTreeSet::new();
        let mut records = Vec::new();
        let mut window = None;
        records
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        for bytes in snapshot.plaintext_objects() {
            if let Some(identity) = record::record_identity(bytes)? {
                if !identities.insert(identity) {
                    return Err(MaintenanceFailure::CatalogUnavailable);
                }
                records.push(MaintenanceTaskRecord(bytes.to_vec()));
                continue;
            }
            if let Some(candidate) = record::window_record(bytes)?
                && window.replace(candidate).is_some()
            {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
        }
        let coordinator = Self::restore(records)?;
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state.window = window;
        drop(state);
        Ok(coordinator)
    }

    /// Publishes the bounded, finite maintenance-window intent before it
    /// defers optional work.
    pub fn set_window_and_persist(
        &self,
        catalog: &Catalog<'_>,
        deferred: impl IntoIterator<Item = MaintenanceTaskClass>,
        until: u64,
        now: u64,
    ) -> Result<(), MaintenanceFailure> {
        if until <= now {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut classes = BTreeSet::new();
        for class in deferred {
            if !class.deferrable() {
                return Err(MaintenanceFailure::InvalidInput);
            }
            classes.insert(class);
        }
        let window = MaintenanceWindow {
            deferred: classes,
            until,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        persist_window(catalog, &window)?;
        state.window = Some(window);
        Ok(())
    }

    fn checkpoint_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(dispatch)
            || checkpoint.completed_inputs as usize > task.task.inputs.len()
            || task
                .checkpoint
                .as_ref()
                .is_some_and(|previous| previous.sequence >= checkpoint.sequence)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut next = task.clone();
        next.checkpoint = Some(checkpoint);
        persist_task_state(catalog, &next, None)?;
        let task = state
            .tasks
            .get_mut(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        *task = next;
        Ok(())
    }

    fn complete_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        {
            let task = next
                .tasks
                .get_mut(&dispatch.identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if task.phase != MaintenanceTaskPhase::Running || task.active_dispatch != Some(dispatch)
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
        assign_terminal_order(&mut next, dispatch.identity)?;
        let task = next
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }
}

impl MaintenanceExecution<'_> {
    /// Durably advances a handler checkpoint through the sole Catalog Writer.
    /// A failed or ambiguous publication leaves the in-memory state unchanged
    /// until the exact retry resolves against the Catalog record.
    pub fn checkpoint_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        checkpoint: MaintenanceCheckpoint,
    ) -> Result<(), MaintenanceFailure> {
        coordinator.checkpoint_and_persist_dispatch(catalog, self.dispatch, checkpoint)
    }

    /// Durably publishes the terminal coordinator outcome before releasing the
    /// execution and its governor reservation.
    pub fn complete_and_persist(
        &self,
        coordinator: &MaintenanceCoordinator,
        catalog: &Catalog<'_>,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        coordinator.complete_and_persist_dispatch(catalog, self.dispatch, succeeded)
    }
}

fn persist_task_state(
    catalog: &Catalog<'_>,
    task: &TaskState,
    removed: Option<MaintenanceTaskId>,
) -> Result<(), MaintenanceFailure> {
    let record = encode_record(task)?;
    let snapshot = catalog.pin().map_err(map_catalog_failure)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(snapshot.object_count())
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    let mut same_record_is_current = false;
    let mut identities = BTreeSet::new();
    for bytes in snapshot.plaintext_objects() {
        match record::record_identity(bytes).map_err(|_| MaintenanceFailure::CatalogUnavailable)? {
            Some(identity) => {
                if !identities.insert(identity) {
                    return Err(MaintenanceFailure::CatalogUnavailable);
                }
                if identity == task.task.identity || Some(identity) == removed {
                    if identity == task.task.identity && bytes == record.as_bytes() {
                        same_record_is_current = true;
                    }
                } else {
                    objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
                }
            },
            None => objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?),
        }
    }
    if same_record_is_current && removed.is_none() {
        return Ok(());
    }
    let record_object = record.catalog_object()?;
    let transaction = record_transaction(
        snapshot.identity().to_bytes(),
        record_object.identity().to_bytes(),
    )?;
    objects.push(record_object);
    let epoch = snapshot
        .format_epoch()
        .ok_or(MaintenanceFailure::CatalogUnavailable)?;
    let proposal =
        CatalogProposal::new(transaction, epoch, objects).map_err(map_catalog_failure)?;
    catalog
        .commit(snapshot.identity(), proposal, None)
        .map_err(map_catalog_failure)?;
    Ok(())
}

fn persist_window(
    catalog: &Catalog<'_>,
    window: &MaintenanceWindow,
) -> Result<(), MaintenanceFailure> {
    let encoded = record::encode_window(window)?;
    let snapshot = catalog.pin().map_err(map_catalog_failure)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(snapshot.object_count())
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    let mut same_window_is_current = false;
    let mut identities = BTreeSet::new();
    let mut saw_window = false;
    for bytes in snapshot.plaintext_objects() {
        if let Some(identity) =
            record::record_identity(bytes).map_err(|_| MaintenanceFailure::CatalogUnavailable)?
        {
            if !identities.insert(identity) {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
            objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
            continue;
        }
        if record::window_record(bytes)
            .map_err(|_| MaintenanceFailure::CatalogUnavailable)?
            .is_some()
        {
            if saw_window {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
            saw_window = true;
            same_window_is_current |= bytes == encoded;
            continue;
        }
        objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?);
    }
    if same_window_is_current {
        return Ok(());
    }
    let object = CatalogObject::new(encoded).map_err(map_catalog_failure)?;
    let transaction =
        record_transaction(snapshot.identity().to_bytes(), object.identity().to_bytes())?;
    objects.push(object);
    let epoch = snapshot
        .format_epoch()
        .ok_or(MaintenanceFailure::CatalogUnavailable)?;
    let proposal =
        CatalogProposal::new(transaction, epoch, objects).map_err(map_catalog_failure)?;
    catalog
        .commit(snapshot.identity(), proposal, None)
        .map_err(map_catalog_failure)?;
    Ok(())
}

fn record_transaction(
    predecessor: [u8; 32],
    identity: [u8; 32],
) -> Result<TransactionId, MaintenanceFailure> {
    let mut material = Vec::new();
    material
        .try_reserve_exact(77)
        .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
    material.extend_from_slice(b"maintenance-transaction-v1");
    material.extend_from_slice(&predecessor);
    material.extend_from_slice(&identity);
    let transaction_identity = CatalogObject::new(material)
        .map_err(map_catalog_failure)?
        .identity()
        .to_bytes();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(
        transaction_identity
            .get(..16)
            .ok_or(MaintenanceFailure::CatalogUnavailable)?,
    );
    if transaction.iter().all(|byte| *byte == 0) {
        transaction[0] = 1;
    }
    TransactionId::new(transaction).map_err(map_catalog_failure)
}

fn map_catalog_failure(_: crate::CatalogFailure) -> MaintenanceFailure {
    MaintenanceFailure::CatalogUnavailable
}
