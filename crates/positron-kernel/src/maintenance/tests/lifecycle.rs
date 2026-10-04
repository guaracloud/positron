use super::*;

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
fn terminal_outcomes_are_retired_only_to_admit_new_live_work() {
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
    let completed = coordinator
        .start_next(1, false)
        .expect("start")
        .expect("queued work");
    coordinator
        .complete(completed.identity(), true)
        .expect("complete");

    coordinator
        .submit(task(
            129,
            MaintenanceTaskClass::Compaction,
            MaintenanceTrigger::Event,
            MaintenancePriority::Ordinary,
            Vec::new(),
        ))
        .expect("terminal slot is retired for live work");
    assert_eq!(
        coordinator.status(completed.identity()),
        Err(MaintenanceFailure::UnknownTask)
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
fn scheduler_order_has_no_priority_fairness_cycle() {
    let scope = |byte| MaintenanceScope::tenant(TenantId::from_bytes([byte; 16]).expect("tenant"));
    let state = |identity, class, task_scope| TaskState {
        task: MaintenanceTask::with_contract(
            MaintenanceTaskId::new([identity; 16]).expect("identity"),
            class,
            task_scope,
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .expect("task"),
        phase: MaintenanceTaskPhase::Queued,
        submitted_at: 0,
        checkpoint: None,
        pause_until: None,
        cancellation_requested: false,
        dispatches: 0,
        terminal_order: None,
        active_dispatch: None,
    };
    let ordinary = state(20, MaintenanceTaskClass::SchemaPromotion, scope(1));
    let required = state(21, MaintenanceTaskClass::SchemaStatistics, scope(2));
    let urgent = state(22, MaintenanceTaskClass::RetentionPublication, scope(3));
    let fairness = BTreeMap::from([
        ((ordinary.task.priority(), ordinary.task.scope()), 0),
        ((required.task.priority(), required.task.scope()), 1),
        ((urgent.task.priority(), urgent.task.scope()), 2),
    ]);

    let cycle = scheduling_order(&ordinary, &required, &fairness, 0) == std::cmp::Ordering::Greater
        && scheduling_order(&required, &urgent, &fairness, 0) == std::cmp::Ordering::Greater
        && scheduling_order(&urgent, &ordinary, &fairness, 0) == std::cmp::Ordering::Greater;

    assert!(!cycle, "priority and fairness must form a total order");
}

#[test]
fn tenant_purge_excludes_a_segment_task_for_the_same_tenant() {
    let coordinator = MaintenanceCoordinator::new();
    let tenant = TenantId::from_bytes([4; 16]).expect("tenant");
    let task = |identity, class, scope| {
        MaintenanceTask::with_contract(
            MaintenanceTaskId::new([identity; 16]).expect("identity"),
            class,
            scope,
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(1, 1).expect("preconditions"),
            Vec::new(),
            Vec::new(),
            ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        )
        .expect("task")
    };
    let purge = task(
        30,
        MaintenanceTaskClass::TenantPurge,
        MaintenanceScope::tenant(tenant),
    );
    let segment = task(
        31,
        MaintenanceTaskClass::Compaction,
        MaintenanceScope::segment(
            tenant,
            SignalKind::Logs,
            VirtualShardId::new(1).expect("shard"),
        ),
    );
    coordinator.submit(purge.clone()).expect("purge accepted");
    coordinator.submit(segment).expect("segment accepted");

    assert_eq!(
        coordinator.start_next(1, false).expect("purge starts"),
        Some(purge)
    );
    assert_eq!(
        coordinator.start_next(2, false).expect("purge owns tenant"),
        None
    );
}

#[test]
fn crash_recovery_honors_cooperative_cancellation_and_retains_durability_work() {
    let coordinator = MaintenanceCoordinator::new();
    let cancellable = task(
        32,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Scheduled,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    let durability = task(
        33,
        MaintenanceTaskClass::ActiveSegmentRoll,
        MaintenanceTrigger::Event,
        MaintenancePriority::Urgent,
        Vec::new(),
    );
    let cancellable_id = cancellable.identity();
    let durability_id = durability.identity();
    coordinator
        .submit(cancellable.clone())
        .expect("cancellable accepted");
    coordinator
        .submit(durability.clone())
        .expect("durability accepted");
    assert_eq!(
        coordinator.start_next(1, false).expect("durability starts"),
        Some(durability)
    );
    assert_eq!(
        coordinator.cancel(durability_id),
        Err(MaintenanceFailure::PreconditionFailed)
    );
    coordinator
        .complete(durability_id, true)
        .expect("durability completes");
    assert_eq!(
        coordinator
            .start_next(2, false)
            .expect("cancellable starts"),
        Some(cancellable)
    );
    coordinator
        .cancel(cancellable_id)
        .expect("cancellation requested");
    coordinator.recover_after_crash().expect("recovered");

    assert_eq!(
        coordinator.status(cancellable_id).expect("status").phase(),
        MaintenanceTaskPhase::Cancelled
    );
}

#[test]
fn a_repeated_urgent_scope_cannot_starve_an_unserved_tenant() {
    let coordinator = MaintenanceCoordinator::new();
    let first = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([10; 16]).expect("identity"),
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceScope::tenant(TenantId::from_bytes([1; 16]).expect("tenant")),
        MaintenanceTrigger::Event,
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
        MaintenanceTrigger::Scheduled,
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
