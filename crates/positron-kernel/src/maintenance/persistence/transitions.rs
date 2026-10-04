//! Prepared durable transition records for maintenance work.

use super::super::*;

/// A not-yet-visible task record prepared by the coordinator for inclusion in
/// a caller-owned Catalog transaction. The ledger uses this only to couple a
/// newly created Snapshot Lease to its expiry work; it cannot inspect or
/// mutate coordinator state directly.
pub(crate) struct QueuedMaintenanceSubmission {
    pub(super) state: TaskState,
    pub(super) record: MaintenanceTaskRecord,
    pub(super) reclaimed_terminal: Option<(MaintenanceTaskId, TaskState)>,
    pub(super) replaced_queued: Option<(MaintenanceTaskId, TaskState)>,
}

/// A terminal replacement for the exact expiry record attached to a released
/// Snapshot Lease. Like a queued submission, it stays opaque until the
/// caller-owned Catalog proposal has committed.
pub(crate) struct SnapshotLeaseExpiryTaskReplacement {
    pub(super) before: TaskState,
    pub(super) after: TaskState,
    pub(super) next_terminal_order: u64,
    pub(super) record: MaintenanceTaskRecord,
}

/// A terminal record reserved by one running Retention Reclamation dispatch.
/// The ledger owns the matching metadata removal and installs it only after
/// the coupled Catalog proposal is durable.
pub(crate) struct RetentionReclamationTaskReplacement {
    pub(super) before: TaskState,
    pub(super) after: TaskState,
    pub(super) next_terminal_order: u64,
    pub(super) record: MaintenanceTaskRecord,
}

/// One terminal record reserved by a running Compaction dispatch. The ledger
/// publishes this record in the same Catalog transaction as the replacement
/// segment manifest, then installs it in the coordinator after that commit.
pub(crate) struct CompactionTaskReplacement {
    pub(super) before: TaskState,
    pub(super) after: TaskState,
    pub(super) next_terminal_order: u64,
    pub(super) record: MaintenanceTaskRecord,
}

/// One terminal Retention Publication and its already-bound queued
/// Reclamation successor. Neither state becomes visible until the ledger has
/// committed both records with the corresponding retired metadata.
pub(crate) struct RetentionPublicationTaskCompletion {
    pub(super) publication_before: TaskState,
    pub(super) publication_after: TaskState,
    pub(super) reclamation: TaskState,
    pub(super) next_terminal_order: u64,
    pub(super) publication_record: MaintenanceTaskRecord,
    pub(super) reclamation_record: MaintenanceTaskRecord,
}

impl RetentionPublicationTaskCompletion {
    pub(crate) fn catalog_objects(&self) -> Result<Vec<CatalogObject>, MaintenanceFailure> {
        Ok(vec![
            self.publication_record.catalog_object()?,
            self.reclamation_record.catalog_object()?,
        ])
    }

    #[must_use]
    pub(crate) const fn publication_identity(&self) -> MaintenanceTaskId {
        self.publication_before.task.identity
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
            .pending_task_transitions
            .contains(&self.publication_before.task.identity)
            || state.tasks.get(&self.publication_before.task.identity)
                != Some(&self.publication_before)
            || !state
                .pending_submissions
                .contains(&self.reclamation.task.identity)
            || state.tasks.contains_key(&self.reclamation.task.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_task_transitions
            .remove(&self.publication_before.task.identity);
        state
            .pending_submissions
            .remove(&self.reclamation.task.identity);
        state
            .tasks
            .insert(self.publication_after.task.identity, self.publication_after);
        state
            .tasks
            .insert(self.reclamation.task.identity, self.reclamation);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn install_reconciled(
        self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if state.tasks.get(&self.publication_before.task.identity) != Some(&self.publication_before)
            || state.tasks.contains_key(&self.reclamation.task.identity)
            || state
                .pending_task_transitions
                .contains(&self.publication_before.task.identity)
            || state
                .pending_submissions
                .contains(&self.reclamation.task.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .tasks
            .insert(self.publication_after.task.identity, self.publication_after);
        state
            .tasks
            .insert(self.reclamation.task.identity, self.reclamation);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn discard(
        &self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state
            .pending_task_transitions
            .remove(&self.publication_before.task.identity);
        state
            .pending_submissions
            .remove(&self.reclamation.task.identity);
        Ok(())
    }
}

impl SnapshotLeaseExpiryTaskReplacement {
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
        if !state
            .pending_task_transitions
            .contains(&self.before.task.identity)
            || state.tasks.get(&self.before.task.identity) != Some(&self.before)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn discard(
        &self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        Ok(())
    }

    pub(crate) fn install_running_completion(
        self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if !state
            .pending_task_transitions
            .contains(&self.before.task.identity)
            || state.tasks.get(&self.before.task.identity) != Some(&self.before)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn install_reconciled_running_completion(
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

impl RetentionReclamationTaskReplacement {
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
        if !state
            .pending_task_transitions
            .contains(&self.before.task.identity)
            || state.tasks.get(&self.before.task.identity) != Some(&self.before)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn install_reconciled(
        self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if state.tasks.get(&self.before.task.identity) != Some(&self.before)
            || state
                .pending_task_transitions
                .contains(&self.before.task.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn discard(
        &self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        Ok(())
    }
}

impl CompactionTaskReplacement {
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
        if !state
            .pending_task_transitions
            .contains(&self.before.task.identity)
            || state.tasks.get(&self.before.task.identity) != Some(&self.before)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn install_reconciled(
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
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
        state.tasks.insert(self.after.task.identity, self.after);
        state.next_terminal_order = state.next_terminal_order.max(self.next_terminal_order);
        Ok(())
    }

    pub(crate) fn discard(
        &self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state
            .pending_task_transitions
            .remove(&self.before.task.identity);
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
            || self
                .replaced_queued
                .as_ref()
                .is_some_and(|(identity, expected)| state.tasks.get(identity) != Some(expected))
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        state.pending_submissions.remove(&self.state.task.identity);
        if let Some((identity, _)) = self.reclaimed_terminal {
            state.pending_terminal_reclamations.remove(&identity);
            super::super::scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
        }
        if let Some((identity, _)) = self.replaced_queued {
            super::super::scheduling::remove_task_and_clear_empty_scope(&mut state, identity)?;
        }
        state.tasks.insert(self.state.task.identity, self.state);
        Ok(())
    }

    pub(crate) fn discard(
        self,
        coordinator: &MaintenanceCoordinator,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = coordinator
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        state.pending_submissions.remove(&self.state.task.identity);
        if let Some((identity, _)) = self.reclaimed_terminal {
            state.pending_terminal_reclamations.remove(&identity);
        }
        Ok(())
    }
}

pub(super) fn matches_catalog_reclamation_predecessor(
    durable: &TaskState,
    durable_record: &[u8],
    live: &TaskState,
) -> Result<bool, MaintenanceFailure> {
    let live_record = encode_record(live)?;
    if live_record.as_bytes() == durable_record {
        return Ok(true);
    }
    // Recovery alone canonically derives this terminal live state from an
    // authenticated durable Running cancellation after a pre-physical
    // terminal-write failure. Keep every persisted field exact while allowing
    // that one phase derivation; ordinary Running descriptors remain refused.
    if durable.phase != MaintenanceTaskPhase::Running
        || !durable.cancellation_requested
        || live.phase != MaintenanceTaskPhase::Cancelled
        || !live.cancellation_requested
        || live.active_dispatch.is_some()
    {
        return Ok(false);
    }
    let mut recovered = durable.clone();
    recovered.phase = MaintenanceTaskPhase::Cancelled;
    Ok(encode_record(&recovered)?.as_bytes() == live_record.as_bytes())
}
