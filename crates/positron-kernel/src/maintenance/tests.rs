use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::{
    Catalog, CatalogObject, CatalogProposal, CatalogSecret, DetectedCapacity, DiskObservation,
    DiskPressureThresholds, FormatEpoch, GovernorPolicy, InstanceId, InventoryCardinalityLimits,
    MountQualification, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, ResourceInventory, StorageKernelResourceAuthority,
    TenantQuota, TransactionId,
};

static NEXT_CATALOG_ROOT: AtomicU64 = AtomicU64::new(0);

struct CatalogRoot(PathBuf);

impl CatalogRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_CATALOG_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-maintenance-catalog-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for CatalogRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn nonzero_id(last: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[15] = last;
    bytes
}

fn task(
    identity: u8,
    class: MaintenanceTaskClass,
    trigger: MaintenanceTrigger,
    _priority: MaintenancePriority,
    inputs: Vec<MaintenanceObjectId>,
) -> MaintenanceTask {
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("stable task identity"),
        class,
        MaintenanceScope::system(),
        trigger,
        MaintenancePreconditions::new(4, 9).expect("valid preconditions"),
        inputs,
        Vec::new(),
        ResourceAmounts::new([64, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
    )
    .expect("bounded task")
}

fn authority() -> (StorageKernelResourceAuthority, TenantId) {
    let tenant = TenantId::from_bytes([90; 16]).expect("test tenant");
    let uniform = |amount| ResourceAmounts::new([amount; 11]);
    let cardinality = InventoryCardinalityLimits::new(1, 8).expect("cardinality");
    let raw = uniform(100_000);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw).expect("detected capacity"),
        OperatorLimits::new(raw).expect("operator limits"),
        RecoveryReserve::new(uniform(10)).expect("recovery reserve"),
        cardinality,
        DiskPressureThresholds::new(20, 30, 40, 50).expect("pressure thresholds"),
        DiskObservation::new(100),
    )
    .expect("inventory");
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(50)).expect("tenant quota")],
        OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))
            .expect("ordinary pools"),
    )
    .expect("policy");
    let recovery_pools = RecoveryPoolCapacities::new(
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(1),
    )
    .expect("recovery pools");
    (
        StorageKernelResourceAuthority::establish_for_test(inventory, policy, recovery_pools)
            .expect("resource authority"),
        tenant,
    )
}

fn tenant_task(identity: u8, tenant: TenantId, reservations: ResourceAmounts) -> MaintenanceTask {
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("identity"),
        MaintenanceTaskClass::Compaction,
        MaintenanceScope::tenant(tenant),
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        reservations,
    )
    .expect("task")
}

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
        MaintenanceTaskClass::Compaction,
    );
    coordinator.submit(task.clone()).expect("task is accepted");

    assert_eq!(
        coordinator.start_next(0, false).expect("scheduler runs"),
        Some(task)
    );
}

#[test]
fn conflicting_copy_on_write_work_waits_for_the_running_owner() {
    let coordinator = MaintenanceCoordinator::new();
    let input = MaintenanceObjectId::new([3; 32]).expect("object identity");
    let first = task(
        1,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        vec![input],
    );
    let second = task(
        2,
        MaintenanceTaskClass::RetentionPublication,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        vec![input],
    );
    coordinator
        .submit_at(first.clone(), 1)
        .expect("first accepted");
    coordinator
        .submit_at(second.clone(), 2)
        .expect("second accepted");

    assert_eq!(
        coordinator.start_next(3, false).expect("first starts"),
        Some(second)
    );
    assert_eq!(
        coordinator.start_next(4, false).expect("conflict waits"),
        None
    );
    coordinator
        .complete(
            MaintenanceTaskId::new([2; 16]).expect("task identity"),
            true,
        )
        .expect("complete");
    assert_eq!(
        coordinator.start_next(5, false).expect("unblocked"),
        Some(first)
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

#[test]
fn durable_checkpoint_restores_the_same_task_after_a_process_restart() {
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        9,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Ordinary,
        Vec::new(),
    );
    let identity = task.identity();
    coordinator.submit(task).expect("accepted");
    coordinator.start_next(1, false).expect("start");
    coordinator
        .checkpoint(
            identity,
            MaintenanceCheckpoint::new(1, 0, vec![9, 8]).expect("checkpoint"),
        )
        .expect("record checkpoint");
    let records = coordinator.durable_records().expect("durable records");

    let restored = MaintenanceCoordinator::restore(records).expect("restore");
    assert_eq!(
        restored
            .status(identity)
            .expect("restored status")
            .checkpoint()
            .map(MaintenanceCheckpoint::opaque_progress),
        Some(&[9, 8][..])
    );
}

#[test]
fn catalog_checkpoint_reopen_restores_one_queued_task_with_its_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(1))?;
    let secret = CatalogSecret::from_owned(Box::new([0x51; 32]), Box::new([0x52; 32]));
    let catalog = Catalog::open(&authority, instance, secret)?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(2))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(b"maintenance catalog basis".to_vec())?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([42; 16]).expect("stable task identity"),
        MaintenanceTaskClass::Compaction,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(4, 9).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    );
    let task = task.expect("bounded task");
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("submission must publish its record");
    let execution = coordinator
        .start_next_with_reservation(&authority, 8, false)
        .expect("dispatch admission")
        .expect("persisted task must dispatch");
    execution
        .checkpoint_and_persist(
            &coordinator,
            &catalog,
            MaintenanceCheckpoint::new(1, 0, vec![4, 2]).expect("checkpoint"),
        )
        .expect("checkpoint must publish");
    drop(execution);
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x51; 32]), Box::new([0x52; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened).expect("restore");
    let status = restored.status(identity).expect("restored status");
    assert_eq!(status.phase(), MaintenanceTaskPhase::Queued);
    assert_eq!(
        status
            .checkpoint()
            .map(MaintenanceCheckpoint::opaque_progress),
        Some(&[4, 2][..])
    );
    let execution = restored
        .start_next_with_reservation(&authority, 9, false)
        .expect("resumed dispatch admission")
        .expect("recovered task must dispatch");
    execution
        .complete_and_persist(&restored, &reopened, true)
        .expect("terminal outcome must publish");
    assert_eq!(
        restored.status(identity).expect("terminal status").phase(),
        MaintenanceTaskPhase::Succeeded
    );
    let durable = reopened.pin()?;
    assert_eq!(
        durable
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1,
        "each task owns one replacement record"
    );
    assert!(
        durable
            .plaintext_objects()
            .any(|bytes| bytes == b"maintenance catalog basis")
    );
    Ok(())
}

#[test]
fn catalog_submission_fault_leaves_no_in_memory_task_and_exact_retry_publishes_once()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(11))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x61; 32]), Box::new([0x62; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(12))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance fault basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([43; 16]).expect("stable task identity"),
        MaintenanceTaskClass::Compaction,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(4, 9).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("bounded task");
    let identity = task.identity();
    let result =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            coordinator.submit_and_persist(&catalog, task.clone(), 7)
        });
    assert_eq!(
        result.expect_err("publication must fail"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        coordinator
            .status(identity)
            .expect_err("state cannot outrun durable publication"),
        MaintenanceFailure::UnknownTask
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        0
    );
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("exact retry must publish the queued task");
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1
    );
    Ok(())
}
