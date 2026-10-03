//! Task-class-specific durable completion preparation.

use super::super::*;
use super::*;

impl MaintenanceCoordinator {
    pub(in super::super) fn reconcile_running_compaction_completion(
        &self,
        dispatch: MaintenanceDispatch,
        durable_record: &[u8],
    ) -> Result<CompactionTaskReplacement, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::Compaction
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let terminal_order = state.next_terminal_order;
        let next_terminal_order = terminal_order
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let mut after = before.clone();
        after.phase = MaintenanceTaskPhase::Succeeded;
        after.active_dispatch = None;
        after.terminal_order = Some(terminal_order);
        let record = encode_record(&after)?;
        if record.as_bytes() != durable_record {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(CompactionTaskReplacement {
            before,
            after,
            next_terminal_order,
            record,
        })
    }
    pub(in super::super) fn prepare_running_compaction_completion(
        &self,
        dispatch: MaintenanceDispatch,
        durable_record: &[u8],
    ) -> Result<CompactionTaskReplacement, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::Compaction
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
            || encode_record(&before)?.as_bytes() != durable_record
            || state.pending_task_transitions.contains(&dispatch.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let terminal_order = state.next_terminal_order;
        let next_terminal_order = terminal_order
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let mut after = before.clone();
        after.phase = MaintenanceTaskPhase::Succeeded;
        after.active_dispatch = None;
        after.terminal_order = Some(terminal_order);
        let record = encode_record(&after)?;
        state.pending_task_transitions.insert(dispatch.identity);
        Ok(CompactionTaskReplacement {
            before,
            after,
            next_terminal_order,
            record,
        })
    }
    /// Reconciles the in-memory coordinator registry from the sole durable
    /// source after a caller observes a previously committed transaction.
    /// This is used by idempotent administration replay when an acknowledgement
    /// was lost after the joint policy-and-task publication.
    pub fn reconcile_from_catalog(&self, catalog: &Catalog<'_>) -> Result<(), MaintenanceFailure> {
        let restored = Self::restore_from_catalog(catalog)?;
        let recovered = restored
            .state
            .into_inner()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        for (identity, candidate) in recovered.tasks {
            if candidate.task.class != MaintenanceTaskClass::CatalogReclamation
                || candidate.phase != MaintenanceTaskPhase::Queued
            {
                continue;
            }
            if let Some(existing) = state.tasks.get(&identity) {
                if existing != &candidate {
                    return Err(MaintenanceFailure::PreconditionFailed);
                }
                continue;
            }
            if state.tasks.len() >= MAX_MAINTENANCE_TASKS {
                return Err(MaintenanceFailure::CapacityExceeded);
            }
            state.tasks.insert(identity, candidate);
        }
        Ok(())
    }
    pub(in super::super) fn prepare_running_retention_reclamation_completion(
        &self,
        dispatch: MaintenanceDispatch,
        durable_record: &[u8],
    ) -> Result<RetentionReclamationTaskReplacement, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::RetentionReclamation
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
            || encode_record(&before)?.as_bytes() != durable_record
            || state.pending_task_transitions.contains(&dispatch.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let terminal_order = state.next_terminal_order;
        let next_terminal_order = terminal_order
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let mut after = before.clone();
        after.phase = MaintenanceTaskPhase::Succeeded;
        after.active_dispatch = None;
        after.terminal_order = Some(terminal_order);
        let record = encode_record(&after)?;
        state.pending_task_transitions.insert(dispatch.identity);
        Ok(RetentionReclamationTaskReplacement {
            before,
            after,
            next_terminal_order,
            record,
        })
    }

    pub(in super::super) fn reconcile_running_retention_reclamation_completion(
        &self,
        dispatch: MaintenanceDispatch,
        terminal_record: &[u8],
    ) -> Result<RetentionReclamationTaskReplacement, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::RetentionReclamation
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
            || state.pending_task_transitions.contains(&dispatch.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let terminal_order = state.next_terminal_order;
        let next_terminal_order = terminal_order
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let mut after = before.clone();
        after.phase = MaintenanceTaskPhase::Succeeded;
        after.active_dispatch = None;
        after.terminal_order = Some(terminal_order);
        let expected = encode_record(&after)?;
        if expected.as_bytes() != terminal_record {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(RetentionReclamationTaskReplacement {
            before,
            after,
            next_terminal_order,
            record: MaintenanceTaskRecord(terminal_record.to_vec()),
        })
    }

    pub(in super::super) fn reconcile_running_retention_publication_completion(
        &self,
        dispatch: MaintenanceDispatch,
        publication_record: &[u8],
        reclamation_record: &[u8],
    ) -> Result<RetentionPublicationTaskCompletion, MaintenanceFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::RetentionPublication
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut publication_after = decode_record(publication_record)?;
        let reclamation = decode_record(reclamation_record)?;
        let terminal_order = state.next_terminal_order;
        let next_terminal_order = terminal_order
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        if !canonical_retention_publication_pair(&before, &publication_after, &reclamation)?
            || state.tasks.contains_key(&reclamation.task.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        publication_after.terminal_order = Some(terminal_order);
        Ok(RetentionPublicationTaskCompletion {
            publication_before: before,
            publication_after,
            reclamation,
            next_terminal_order,
            publication_record: MaintenanceTaskRecord(publication_record.to_vec()),
            reclamation_record: MaintenanceTaskRecord(reclamation_record.to_vec()),
        })
    }
    pub(in super::super) fn prepare_running_retention_publication_completion(
        &self,
        dispatch: MaintenanceDispatch,
        binding: RetentionPublicationBinding<'_, '_>,
    ) -> Result<RetentionPublicationTaskCompletion, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&dispatch.identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task != *binding.publication
            || before.task.class != MaintenanceTaskClass::RetentionPublication
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
            || encode_record(&before)?.as_bytes() != binding.durable_record
            || state.pending_task_transitions.contains(&dispatch.identity)
            || state.tasks.contains_key(&binding.reclamation.identity)
            || state
                .pending_submissions
                .contains(&binding.reclamation.identity)
            || binding.reclamation.class != MaintenanceTaskClass::RetentionReclamation
            || binding.reclamation.scope != before.task.scope
            || binding.reclamation.trigger != MaintenanceTrigger::Event
            || binding.reclamation.preconditions != before.task.preconditions
            || binding.reclamation.inputs != before.task.outputs
            || !binding.reclamation.outputs.is_empty()
            || binding.reclamation.reservations != before.task.reservations
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let occupied = state
            .tasks
            .len()
            .checked_add(state.pending_submissions.len())
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        if occupied >= MAX_MAINTENANCE_TASKS {
            return Err(MaintenanceFailure::CapacityExceeded);
        }
        let terminal_order = state.next_terminal_order;
        let next_terminal_order = terminal_order
            .checked_add(1)
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let mut publication_after = before.clone();
        publication_after.phase = MaintenanceTaskPhase::Succeeded;
        publication_after.cancellation_requested = false;
        publication_after.active_dispatch = None;
        publication_after.terminal_order = Some(terminal_order);
        let reclamation = TaskState {
            task: binding.reclamation,
            phase: MaintenanceTaskPhase::Queued,
            submitted_at: before.submitted_at,
            checkpoint: None,
            pause_until: None,
            cancellation_requested: false,
            dispatches: 0,
            terminal_order: None,
            active_dispatch: None,
        };
        let publication_record = encode_record(&publication_after)?;
        let reclamation_record = encode_record(&reclamation)?;
        state.pending_task_transitions.insert(dispatch.identity);
        state.pending_submissions.insert(reclamation.task.identity);
        Ok(RetentionPublicationTaskCompletion {
            publication_before: before,
            publication_after,
            reclamation,
            next_terminal_order,
            publication_record,
            reclamation_record,
        })
    }
    pub(in super::super) fn reconcile_running_snapshot_lease_expiry_completion(
        &self,
        dispatch: MaintenanceDispatch,
        durable_record: &[u8],
    ) -> Result<SnapshotLeaseExpiryTaskReplacement, MaintenanceFailure> {
        let identity = dispatch.identity;
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
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut next = state.clone();
        let after = next
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        after.phase = MaintenanceTaskPhase::Succeeded;
        after.active_dispatch = None;
        assign_terminal_order(&mut next, identity)?;
        let after = next
            .tasks
            .get(&identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let record = encode_record(&after)?;
        if record.as_bytes() != durable_record {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        Ok(SnapshotLeaseExpiryTaskReplacement {
            before,
            after,
            next_terminal_order: next.next_terminal_order,
            record,
        })
    }
    pub(in super::super) fn prepare_running_snapshot_lease_expiry_completion(
        &self,
        dispatch: MaintenanceDispatch,
        binding: SnapshotLeaseExpiryBinding<'_>,
    ) -> Result<SnapshotLeaseExpiryTaskReplacement, MaintenanceFailure> {
        if dispatch.coordinator_id != self.coordinator_id {
            return Err(MaintenanceFailure::InvalidTransition);
        }
        let identity = MaintenanceTaskId::new(binding.identity.to_bytes())?;
        let expected_input = MaintenanceObjectId::new(binding.lease_object.to_bytes())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        let before = state
            .tasks
            .get(&identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        if before.task.class != MaintenanceTaskClass::SnapshotLeaseExpiry
            || before.task.scope != binding.scope
            || before.task.trigger != MaintenanceTrigger::Scheduled
            || before.task.preconditions.catalog_generation != binding.predecessor_generation
            || before.task.preconditions.resource_generation != 1
            || before.task.inputs.as_slice() != [expected_input]
            || !before.task.outputs.is_empty()
            || before.task.not_before != binding.not_before
            || encode_record(&before)?.as_bytes() != binding.durable_record
            || before.phase != MaintenanceTaskPhase::Running
            || before.active_dispatch != Some(dispatch)
            || before.cancellation_requested
            || state.pending_task_transitions.contains(&identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let mut next = state.clone();
        let after = next
            .tasks
            .get_mut(&identity)
            .ok_or(MaintenanceFailure::UnknownTask)?;
        after.phase = MaintenanceTaskPhase::Succeeded;
        after.cancellation_requested = false;
        after.active_dispatch = None;
        assign_terminal_order(&mut next, identity)?;
        let after = next
            .tasks
            .get(&identity)
            .cloned()
            .ok_or(MaintenanceFailure::UnknownTask)?;
        let record = encode_record(&after)?;
        state.pending_task_transitions.insert(identity);
        Ok(SnapshotLeaseExpiryTaskReplacement {
            before,
            after,
            next_terminal_order: next.next_terminal_order,
            record,
        })
    }

    pub(crate) fn install_snapshot_lease_expiry_cancellations(
        &self,
        cancellations: Vec<SnapshotLeaseExpiryTaskReplacement>,
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
                !state
                    .pending_task_transitions
                    .contains(&cancellation.before.task.identity)
                    || state.tasks.get(&cancellation.before.task.identity)
                        != Some(&cancellation.before)
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
                .pending_task_transitions
                .remove(&cancellation.before.task.identity);
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
        cancellation: SnapshotLeaseExpiryTaskReplacement,
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
            .pending_task_transitions
            .contains(&cancellation.before.task.identity)
            || state.tasks.get(&cancellation.before.task.identity) != Some(&cancellation.before)
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
        state
            .pending_task_transitions
            .remove(&cancellation.before.task.identity);
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
    ) -> Result<Option<SnapshotLeaseExpiryTaskReplacement>, MaintenanceFailure> {
        let identity = MaintenanceTaskId::new(identity.to_bytes())?;
        let expected_input = MaintenanceObjectId::new(lease_object.to_bytes())?;
        let mut state = self
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
        if state.pending_task_transitions.contains(&identity) {
            return Err(MaintenanceFailure::PreconditionFailed);
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
        state.pending_task_transitions.insert(identity);
        Ok(Some(SnapshotLeaseExpiryTaskReplacement {
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
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let reclaimed_terminal = if occupied >= MAX_MAINTENANCE_TASKS {
            let mut prospective = state.clone();
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
            replaced_queued: None,
        })
    }

    /// Reserves one system-scoped Catalog reclamation descriptor for a
    /// caller-owned Catalog proposal.  The descriptor is invisible until its
    /// companion proposal commits, exactly like the coupled lease-expiry
    /// descriptor above.
    pub(crate) fn prepare_catalog_reclamation(
        &self,
        task: MaintenanceTask,
        submitted_at: u64,
        predecessor_record: Option<&[u8]>,
    ) -> Result<QueuedMaintenanceSubmission, MaintenanceFailure> {
        if task.class != MaintenanceTaskClass::CatalogReclamation
            || task.scope != MaintenanceScope::System
            || task.trigger != MaintenanceTrigger::Event
        {
            return Err(MaintenanceFailure::InvalidInput);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MaintenanceFailure::ConcurrentAccess)?;
        if state.tasks.contains_key(&task.identity)
            || state.pending_submissions.contains(&task.identity)
        {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let predecessor = match predecessor_record {
            Some(record) => {
                let predecessor = decode_record(record)?;
                let live = state
                    .tasks
                    .get(&predecessor.task.identity)
                    .ok_or(MaintenanceFailure::PreconditionFailed)?;
                if predecessor.task.class != MaintenanceTaskClass::CatalogReclamation
                    || predecessor.task.scope != MaintenanceScope::System
                    || !matches_catalog_reclamation_predecessor(&predecessor, record, live)?
                {
                    return Err(MaintenanceFailure::PreconditionFailed);
                }
                // Terminal eviction order is coordinator-local rather than a
                // durable task-record field. The authenticated predecessor
                // record has already matched the live state or the one
                // recovery-defined cancelled form above.
                Some(live.clone())
            },
            None => None,
        };
        let replaced_queued = predecessor.as_ref().and_then(|predecessor| {
            (predecessor.phase == MaintenanceTaskPhase::Queued)
                .then(|| (predecessor.task.identity, predecessor.clone()))
        });
        let predecessor_terminal = predecessor.as_ref().and_then(|predecessor| {
            matches!(
                predecessor.phase,
                MaintenanceTaskPhase::Cancelled
                    | MaintenanceTaskPhase::Succeeded
                    | MaintenanceTaskPhase::Failed
            )
            .then(|| (predecessor.task.identity, predecessor.clone()))
        });
        if predecessor.is_some() && replaced_queued.is_none() && predecessor_terminal.is_none() {
            return Err(MaintenanceFailure::PreconditionFailed);
        }
        let occupied = state
            .tasks
            .len()
            .checked_add(state.pending_submissions.len())
            .and_then(|value| {
                value.checked_sub(usize::from(
                    replaced_queued.is_some() || predecessor_terminal.is_some(),
                ))
            })
            .ok_or(MaintenanceFailure::CapacityExceeded)?;
        let reclaimed_terminal = if let Some(terminal) = predecessor_terminal {
            Some(terminal)
        } else if occupied >= MAX_MAINTENANCE_TASKS {
            let mut prospective = state.clone();
            let identity = reclaim_terminal_slot(&mut prospective)?
                .ok_or(MaintenanceFailure::CapacityExceeded)?;
            Some((
                identity,
                state
                    .tasks
                    .get(&identity)
                    .cloned()
                    .ok_or(MaintenanceFailure::UnknownTask)?,
            ))
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
            submitted_at,
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
            replaced_queued,
        })
    }
}
