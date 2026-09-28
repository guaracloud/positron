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

impl MaintenanceCoordinator {
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
        let removed = if next.tasks.len() >= MAX_MAINTENANCE_TASKS {
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

    /// Recovers the complete bounded task registry from authenticated Catalog
    /// objects. Running work never owns durable capacity after a process exit,
    /// so it is returned to its queued checkpoint before any handler resumes.
    pub fn restore_from_catalog(catalog: &Catalog<'_>) -> Result<Self, MaintenanceFailure> {
        let snapshot = catalog.pin().map_err(map_catalog_failure)?;
        let mut identities = BTreeSet::new();
        let mut records = Vec::new();
        records
            .try_reserve_exact(snapshot.object_count())
            .map_err(|_| MaintenanceFailure::CapacityExceeded)?;
        for bytes in snapshot.plaintext_objects() {
            let Some(identity) = record::record_identity(bytes)? else {
                continue;
            };
            if !identities.insert(identity) {
                return Err(MaintenanceFailure::CatalogUnavailable);
            }
            records.push(MaintenanceTaskRecord(bytes.to_vec()));
        }
        Self::restore(records)
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
        self,
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
    for bytes in snapshot.plaintext_objects() {
        match record::record_identity(bytes)? {
            Some(identity) if identity == task.task.identity || Some(identity) == removed => {
                if identity == task.task.identity && bytes == record.as_bytes() {
                    same_record_is_current = true;
                }
            },
            Some(_) | None => {
                objects.push(CatalogObject::new(bytes.to_vec()).map_err(map_catalog_failure)?)
            },
        }
    }
    if same_record_is_current && removed.is_none() {
        return Ok(());
    }
    let record_object = record.catalog_object()?;
    let transaction = record_transaction(record_object.identity().to_bytes())?;
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

fn record_transaction(identity: [u8; 32]) -> Result<TransactionId, MaintenanceFailure> {
    let mut transaction = [0; 16];
    transaction.copy_from_slice(
        identity
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
