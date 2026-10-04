use super::*;

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
        MaintenanceTaskClass::SchemaStatistics,
    );
    coordinator.submit(task.clone()).expect("task is accepted");

    assert_eq!(
        coordinator.start_next(0, false).expect("scheduler runs"),
        Some(task)
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
fn uncertain_clock_also_pauses_scheduled_destruction() {
    let coordinator = MaintenanceCoordinator::new();
    let scheduled_retention = task(
        13,
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceTrigger::Scheduled,
        MaintenancePriority::Required,
        Vec::new(),
    );
    let safe_compaction = task(
        14,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    coordinator
        .submit(scheduled_retention)
        .expect("retention accepted");
    coordinator
        .submit(safe_compaction.clone())
        .expect("safe work accepted");

    assert_eq!(
        coordinator.start_next(1, true).expect("scheduler runs"),
        Some(safe_compaction)
    );
}

#[test]
fn execution_rejects_a_foreign_coordinator_before_observing_its_task_map() {
    let (authority, tenant) = authority();
    let first = MaintenanceCoordinator::new();
    let second = MaintenanceCoordinator::new();
    let task = tenant_task(15, tenant, ResourceAmounts::new([1; 11]));
    first.submit(task).expect("accepted");
    let execution = first
        .start_next_with_reservation(&authority, 1, false)
        .expect("admitted")
        .expect("execution");

    assert_eq!(
        execution.checkpoint(
            &second,
            MaintenanceCheckpoint::new(1, 0, Vec::new()).expect("checkpoint"),
        ),
        Err(MaintenanceFailure::InvalidTransition)
    );
}

#[test]
fn reservation_refusal_leaves_the_task_queued_without_a_dispatch_attempt() {
    let (authority, tenant) = authority();
    let coordinator = MaintenanceCoordinator::new();
    let task = tenant_task(16, tenant, ResourceAmounts::new([51; 11]));
    let identity = task.identity();
    coordinator.submit(task).expect("accepted");

    assert!(matches!(
        coordinator.start_next_with_reservation(&authority, 1, false),
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    ));
    assert_eq!(
        coordinator.status(identity).expect("status").phase(),
        MaintenanceTaskPhase::Queued
    );
}

#[test]
fn system_scoped_ordinary_maintenance_reserves_global_governor_capacity() {
    let (authority, _) = authority();
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([18; 16]).expect("identity"),
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceScope::system(),
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([51; 11]),
    )
    .expect("task");
    coordinator.submit(task).expect("accepted");
    let next = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([19; 16]).expect("identity"),
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceScope::system(),
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([51; 11]),
    )
    .expect("task");
    let next_identity = next.identity();
    coordinator.submit(next).expect("accepted");

    let execution = coordinator
        .start_next_with_reservation(&authority, 1, false)
        .expect("global ordinary capacity admits system work")
        .expect("execution");
    assert_eq!(
        authority
            .governor()
            .inspect()
            .expect("snapshot")
            .outstanding_ordinary(),
        1
    );
    assert_eq!(
        authority
            .governor()
            .inspect()
            .expect("snapshot")
            .outstanding_recovery(),
        0
    );
    assert!(matches!(
        coordinator.start_next_with_reservation(&authority, 1, false),
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    ));
    execution
        .complete(&coordinator, true)
        .expect("completion applies to the admitted attempt");
    let replacement = coordinator
        .start_next_with_reservation(&authority, 2, false)
        .expect("released global capacity admits the queued task")
        .expect("execution");
    assert_eq!(replacement.task().identity(), next_identity);
    replacement
        .complete(&coordinator, true)
        .expect("replacement completes");
}

#[test]
fn stale_execution_cannot_checkpoint_after_crash_resume_starts_a_new_attempt() {
    let (authority, tenant) = authority();
    let coordinator = MaintenanceCoordinator::new();
    let task = tenant_task(17, tenant, ResourceAmounts::new([1; 11]));
    coordinator.submit(task).expect("accepted");
    let stale = coordinator
        .start_next_with_reservation(&authority, 1, false)
        .expect("admitted")
        .expect("first attempt");
    coordinator.recover_after_crash().expect("recovered");
    let current = coordinator
        .start_next_with_reservation(&authority, 2, false)
        .expect("admitted")
        .expect("second attempt");

    assert_eq!(
        stale.checkpoint(
            &coordinator,
            MaintenanceCheckpoint::new(1, 0, Vec::new()).expect("checkpoint"),
        ),
        Err(MaintenanceFailure::InvalidTransition)
    );
    current
        .checkpoint(
            &coordinator,
            MaintenanceCheckpoint::new(1, 0, Vec::new()).expect("checkpoint"),
        )
        .expect("current attempt owns checkpoint");
}

#[test]
fn finite_window_expires_and_never_defers_trusted_emergency_compaction() {
    let (authority, _) = authority();
    let coordinator = MaintenanceCoordinator::new();
    let scheduled = task(
        18,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Scheduled,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    coordinator
        .set_window([MaintenanceTaskClass::Compaction], 10, 0)
        .expect("finite window");
    coordinator.submit(scheduled.clone()).expect("accepted");
    assert_eq!(coordinator.start_next(9, false).expect("deferred"), None);
    assert_eq!(
        coordinator.start_next(10, false).expect("window expired"),
        Some(scheduled)
    );

    let emergency = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([19; 16]).expect("identity"),
        MaintenanceTaskClass::Compaction,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("compaction");
    coordinator
        .set_window([MaintenanceTaskClass::Compaction], 20, 10)
        .expect("finite window");
    assert_eq!(
        coordinator.submit_emergency_compaction(&authority, emergency.clone()),
        Err(MaintenanceFailure::PreconditionFailed)
    );
    assert_eq!(
        authority
            .observe_disk_for_test(DiskObservation::new(20))
            .expect("hard pressure observed"),
        DiskPressureState::HardPressure
    );
    let emergency = coordinator
        .submit_emergency_compaction(&authority, emergency)
        .expect("pressure-proven emergency accepted");
    assert_eq!(
        recovery_kind(&emergency),
        Some(RecoveryWorkKind::EmergencyCompaction)
    );
    assert_eq!(
        coordinator
            .start_next(11, false)
            .expect("emergency remains eligible"),
        Some(emergency)
    );
}

#[test]
fn durability_outranks_an_aged_lower_class_without_promoting_untrusted_recovery_work() {
    let coordinator = MaintenanceCoordinator::new();
    let ordinary = task(
        20,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Scheduled,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    let durability = task(
        21,
        MaintenanceTaskClass::ActiveSegmentRoll,
        MaintenanceTrigger::Event,
        MaintenancePriority::Urgent,
        Vec::new(),
    );
    let event_compaction = task(
        22,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Urgent,
        Vec::new(),
    );
    coordinator
        .submit_at(ordinary, 0)
        .expect("ordinary accepted");
    coordinator
        .submit_at(durability.clone(), 59)
        .expect("durability accepted");
    assert_eq!(
        coordinator.start_next(60, false).expect("scheduler runs"),
        Some(durability)
    );
    assert_eq!(event_compaction.priority(), MaintenancePriority::Required);
    assert_eq!(recovery_kind(&event_compaction), None);
}
