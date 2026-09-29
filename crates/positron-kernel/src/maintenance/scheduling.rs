use super::*;

pub(super) fn eligible_task_ids(
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
            && task.task.not_before <= now
            && !state.pending_cancellations.contains(identity)
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

pub(super) fn dispatch_task(
    state: &mut CoordinatorState,
    coordinator_id: u64,
    identity: MaintenanceTaskId,
    now: u64,
) -> Result<MaintenanceDispatch, MaintenanceFailure> {
    require_unreserved_task_transition(state, identity)?;
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

pub(super) fn reserve_task<'authority>(
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
    let claim = match task.scope.tenant_id() {
        Some(tenant) => WorkClaim::tenant(
            tenant,
            WorkKind::OrdinaryMaintenanceBackup,
            task.reservations,
        ),
        None => WorkClaim::system_maintenance(task.reservations),
    }
    .map_err(|_| ())?;
    authority
        .governor()
        .reserve(claim)
        .map(MaintenanceReservation::Ordinary)
        .map_err(|_| ())
}

pub(super) fn recovery_kind(task: &MaintenanceTask) -> Option<RecoveryWorkKind> {
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

pub(super) fn retains_until_completion(task: &MaintenanceTask) -> bool {
    matches!(
        recovery_kind(task),
        Some(RecoveryWorkKind::DurabilityCompletion)
    )
}

pub(super) fn assign_terminal_order(
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

pub(super) fn reclaim_terminal_slot(
    state: &mut CoordinatorState,
) -> Result<Option<MaintenanceTaskId>, MaintenanceFailure> {
    let candidate = state
        .tasks
        .iter()
        .filter(|(identity, task)| {
            !state.pending_terminal_reclamations.contains(*identity)
                && matches!(
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
        return Ok(None);
    };
    remove_task_and_clear_empty_scope(state, identity)?;
    Ok(Some(identity))
}

pub(super) fn remove_task_and_clear_empty_scope(
    state: &mut CoordinatorState,
    identity: MaintenanceTaskId,
) -> Result<(), MaintenanceFailure> {
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
    Ok(())
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

pub(super) fn scheduling_order(
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
