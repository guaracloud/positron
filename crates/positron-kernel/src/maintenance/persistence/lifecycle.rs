//! Coordinator dispatch completion, cancellation, and same-process recovery.

use super::super::*;
use super::*;

impl MaintenanceCoordinator {
    pub(in super::super) fn checkpoint_and_persist_dispatch(
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
        super::require_unreserved_task_transition(&state, dispatch.identity)?;
        let task = state
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.phase != MaintenanceTaskPhase::Running
            || matches!(
                task.task.class,
                MaintenanceTaskClass::RetentionPublication
                    | MaintenanceTaskClass::RetentionReclamation
            )
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

    pub(in super::super) fn complete_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        succeeded: bool,
    ) -> Result<(), MaintenanceFailure> {
        self.complete_and_persist_dispatch_inner(catalog, dispatch, succeeded, None)
    }

    fn complete_and_persist_dispatch_inner(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        succeeded: bool,
        execution: Option<&MaintenanceExecution<'_>>,
    ) -> Result<(), MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        super::require_unreserved_task_transition(&state, dispatch.identity)?;
        if state.tasks.get(&dispatch.identity).is_some_and(|task| {
            matches!(
                task.task.class,
                MaintenanceTaskClass::RetentionPublication
                    | MaintenanceTaskClass::RetentionReclamation
            )
        }) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
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
        match execution {
            Some(execution) => persist_task_state_admitted(catalog, task, None, execution)?,
            None => persist_task_state(catalog, task, None)?,
        }
        *state = next;
        Ok(())
    }

    pub(in super::super) fn complete_and_persist_admitted_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        succeeded: bool,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<(), MaintenanceFailure> {
        self.complete_and_persist_dispatch_inner(catalog, dispatch, succeeded, Some(execution))
    }

    pub(in super::super) fn complete_catalog_reclamation_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
    ) -> Result<(), MaintenanceFailure> {
        self.complete_and_persist_dispatch(catalog, dispatch, true)
    }

    pub(in super::super) fn requeue_catalog_reclamation_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
    ) -> Result<(), MaintenanceFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let task = next
            .tasks
            .get_mut(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.task.class != MaintenanceTaskClass::CatalogReclamation
            || task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(dispatch)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        // A cancellation observed after a physical unlink cannot terminalize
        // the still-unfinished prefix. Requeue the exact descriptor and clear
        // that request so its authenticated retry can finish idempotently.
        task.cancellation_requested = false;
        task.phase = MaintenanceTaskPhase::Queued;
        task.active_dispatch = None;
        if let Err(failure) = persist_task_state(catalog, task, None) {
            drop(state);
            self.restore_catalog_reclamation_after_requeue_failure(catalog, dispatch)?;
            return Err(failure);
        }
        *state = next;
        Ok(())
    }

    /// Reconciles the sole affected descriptor after a post-physical-unlink
    /// requeue write is ambiguous. A durable Running record restarts as its
    /// exact queued retry, so the live worker need not strand it until restart.
    fn restore_catalog_reclamation_after_requeue_failure(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
    ) -> Result<(), MaintenanceFailure> {
        let restored = Self::restore_from_catalog(catalog)?;
        let mut recovered = restored
            .state
            .into_inner()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut candidate = recovered
            .tasks
            .remove(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if candidate.task.class != MaintenanceTaskClass::CatalogReclamation {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        if candidate.phase == MaintenanceTaskPhase::Cancelled {
            // This path is reached only after the handler has made physical
            // progress. Do not turn that partial prefix into a terminal
            // cancellation merely because the failed requeue left a durable
            // Running record with a cancellation request.
            candidate.phase = MaintenanceTaskPhase::Queued;
            candidate.cancellation_requested = false;
            candidate.active_dispatch = None;
        }
        if !matches!(
            candidate.phase,
            MaintenanceTaskPhase::Queued | MaintenanceTaskPhase::Succeeded
        ) {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let current = state
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if current.task.class != MaintenanceTaskClass::CatalogReclamation
            || current.phase != MaintenanceTaskPhase::Running
            || current.active_dispatch != Some(dispatch)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        state.tasks.insert(dispatch.identity, candidate);
        state.next_terminal_order = state.next_terminal_order.max(recovered.next_terminal_order);
        let queued = state
            .tasks
            .get(&dispatch.identity)
            .is_some_and(|task| task.phase == MaintenanceTaskPhase::Queued);
        let recovered = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        drop(state);
        if queued {
            // If this confirmation also faults, keep the recovered queued
            // descriptor live. The next bounded wake reacquires it from the
            // exact durable Running record; it is never stranded Running.
            persist_task_state(catalog, &recovered, None)?;
        }
        Ok(())
    }

    /// Reconciles a pre-physical cancellation after its terminal record write
    /// is unavailable or acknowledgement-ambiguous. Recovery maps the exact
    /// durable Running-with-cancellation record to Cancelled, so replacing
    /// only this live descriptor neither restarts physical work nor disturbs
    /// another coordinator task.
    pub(in super::super) fn restore_cancelled_catalog_reclamation_after_terminal_failure(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
    ) -> Result<(), MaintenanceFailure> {
        let restored = Self::restore_from_catalog(catalog)?;
        let recovered = restored
            .state
            .into_inner()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let candidate = recovered
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if candidate.task.class != MaintenanceTaskClass::CatalogReclamation
            || candidate.phase != MaintenanceTaskPhase::Cancelled
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let current = state
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if current.task.class != MaintenanceTaskClass::CatalogReclamation
            || current.phase != MaintenanceTaskPhase::Running
            || !current.cancellation_requested
            || current.active_dispatch != Some(dispatch)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        state.tasks.insert(dispatch.identity, candidate);
        state.next_terminal_order = state.next_terminal_order.max(recovered.next_terminal_order);
        Ok(())
    }

    pub(in super::super) fn verify_running_catalog_reclamation_dispatch(
        &self,
        dispatch: MaintenanceDispatch,
        durable_record: &[u8],
    ) -> Result<(), MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.task.class != MaintenanceTaskClass::CatalogReclamation
            || task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(dispatch)
            || encode_record(task)?.as_bytes() != durable_record
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(())
    }

    pub(in super::super) fn catalog_reclamation_cancellation_requested_dispatch(
        &self,
        dispatch: MaintenanceDispatch,
    ) -> Result<bool, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let task = state
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.task.class != MaintenanceTaskClass::CatalogReclamation
            || task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(dispatch)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        Ok(task.cancellation_requested)
    }

    pub(in super::super) fn requeue_admitted_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<(), MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut next = state.clone();
        let task = next
            .tasks
            .get_mut(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.task.class != MaintenanceTaskClass::GovernanceAuditCheckpoint
            || task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(dispatch)
            || task.cancellation_requested
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        task.phase = MaintenanceTaskPhase::Queued;
        task.active_dispatch = None;
        persist_task_state_admitted(catalog, task, None, execution)?;
        *state = next;
        Ok(())
    }

    pub(in super::super) fn release_admitted_dispatch_for_recovery(
        &self,
        dispatch: MaintenanceDispatch,
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
            .get_mut(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if task.task.class != MaintenanceTaskClass::GovernanceAuditCheckpoint
            || task.phase != MaintenanceTaskPhase::Running
            || task.active_dispatch != Some(dispatch)
        {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        // A terminal write and its durable requeue both failed. The execution
        // is about to release its reservation, so retain no live owner in this
        // coordinator. The authenticated Catalog record remains the recovery
        // authority; the next exact attach republishes Running before it signs
        // or terminalizes anything.
        task.phase = MaintenanceTaskPhase::Queued;
        task.active_dispatch = None;
        Ok(())
    }

    pub(in super::super) fn cancel_running_retention_publication_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
    ) -> Result<(), MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        super::require_unreserved_task_transition(&state, dispatch.identity)?;
        let mut next = state.clone();
        {
            let task = next
                .tasks
                .get_mut(&dispatch.identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if task.task.class != MaintenanceTaskClass::RetentionPublication
                || task.phase != MaintenanceTaskPhase::Running
                || task.active_dispatch != Some(dispatch)
                || !task.cancellation_requested
            {
                return Err(MaintenanceFailure::InvalidTransition);
            }
            task.phase = MaintenanceTaskPhase::Cancelled;
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

    pub(in super::super) fn requeue_running_retention_reclamation_and_persist_dispatch(
        &self,
        catalog: &Catalog<'_>,
        dispatch: MaintenanceDispatch,
        durable_record: &[u8],
    ) -> Result<(), MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        super::require_unreserved_task_transition(&state, dispatch.identity)?;
        let mut next = state.clone();
        {
            let task = next
                .tasks
                .get_mut(&dispatch.identity)
                .ok_or(MaintenanceFailure::UnknownTask)?;
            if task.task.class != MaintenanceTaskClass::RetentionReclamation
                || task.phase != MaintenanceTaskPhase::Running
                || task.active_dispatch != Some(dispatch)
                || task.cancellation_requested
                || encode_record(task)?.as_bytes() != durable_record
            {
                return Err(MaintenanceFailure::InvalidTransition);
            }
            task.phase = MaintenanceTaskPhase::Queued;
            task.active_dispatch = None;
        }
        let task = next
            .tasks
            .get(&dispatch.identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        persist_task_state(catalog, task, None)?;
        *state = next;
        Ok(())
    }
}
