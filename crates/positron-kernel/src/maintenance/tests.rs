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

#[path = "tests/conflicts.rs"]
mod conflicts;
#[path = "tests/poison.rs"]
mod poison;
#[path = "tests/retention_publication.rs"]
mod retention_publication;

static NEXT_CATALOG_ROOT: AtomicU64 = AtomicU64::new(0);

#[test]
fn governance_audit_checkpoint_binding_rejects_malformed_checkpoints() {
    let valid = GovernanceAuditCheckpointBinding::new(1, [1; 32], [2; 32])
        .expect("nonzero binding")
        .checkpoint()
        .expect("bounded checkpoint");
    assert!(GovernanceAuditCheckpointBinding::from_checkpoint(Some(&valid)).is_ok());

    for checkpoint in [
        None,
        Some(MaintenanceCheckpoint::new(2, 0, valid.opaque_progress().to_vec()).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 1, valid.opaque_progress().to_vec()).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 0, vec![0; 79]).expect("shape")),
        Some(MaintenanceCheckpoint::new(1, 0, vec![0; 80]).expect("shape")),
    ] {
        assert_eq!(
            GovernanceAuditCheckpointBinding::from_checkpoint(checkpoint.as_ref()),
            Err(MaintenanceFailure::InvalidInput)
        );
    }
}

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

fn catalog_task(identity: u8) -> MaintenanceTask {
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("stable task identity"),
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(4, 9).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("bounded task")
}

#[test]
fn generic_submission_cannot_persist_a_compaction_without_its_typed_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(0x57))?,
        CatalogSecret::from_owned(Box::new([0x58; 32]), Box::new([0x59; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = task(
        0x5a,
        MaintenanceTaskClass::Compaction,
        MaintenanceTrigger::Event,
        MaintenancePriority::Required,
        Vec::new(),
    );
    assert_eq!(
        coordinator
            .submit_and_persist(&catalog, task, 1)
            .expect_err("generic ingress must not create an unbound compaction"),
        MaintenanceFailure::InvalidInput
    );
    assert!(
        coordinator
            .durable_records()
            .expect("refused ingress has no durable task record")
            .is_empty()
    );
    Ok(())
}

fn snapshot_lease_expiry_task(
    identity: crate::SnapshotLeaseId,
    scope: MaintenanceScope,
    lease_object: crate::CatalogObjectId,
) -> MaintenanceTask {
    MaintenanceTask::with_contract_not_before(
        MaintenanceTaskId::new(identity.to_bytes()).expect("lease task identity"),
        MaintenanceTaskClass::SnapshotLeaseExpiry,
        scope,
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(7, 1).expect("preconditions"),
        vec![MaintenanceObjectId::new(lease_object.to_bytes()).expect("lease object input")],
        Vec::new(),
        ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        10,
    )
    .expect("snapshot expiry task")
}

#[test]
fn installed_class_selection_dispatches_supported_work_and_leaves_other_classes_queued()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(66))?,
        CatalogSecret::from_owned(Box::new([0x67; 32]), Box::new([0x68; 32])),
    )?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(69))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(b"class selection basis".to_vec())?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let coordinator = MaintenanceCoordinator::new();
    let unsupported = MaintenanceTask::new(
        MaintenanceTaskId::new(nonzero_id(70)).expect("unsupported task identity"),
        MaintenanceTaskClass::SchemaPromotion,
    );
    let unsupported_id = unsupported.identity();
    coordinator
        .submit_and_persist(&catalog, unsupported, 1)
        .expect("unsupported task persists");
    let lease = crate::SnapshotLeaseId::new([71; 16])?;
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([0x43; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let lease_object = CatalogObject::new(b"class selection lease binding".to_vec())?.identity();
    let supported = snapshot_lease_expiry_task(lease, scope, lease_object);
    let supported_id = supported.identity();
    coordinator
        .submit_and_persist(&catalog, supported, 1)
        .expect("supported task persists");

    let execution = coordinator
        .start_next_with_reservation_and_persist_for_classes(
            &catalog,
            &authority,
            10,
            false,
            &[MaintenanceTaskClass::SnapshotLeaseExpiry],
        )
        .expect("installed handler selection")
        .expect("the installed handler selects its eligible task");
    assert_eq!(execution.task().identity(), supported_id);
    assert_eq!(
        coordinator
            .status(unsupported_id)
            .expect("unsupported task")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the worker must not mark an unsupported class Running"
    );
    Ok(())
}

#[test]
fn prepared_lease_expiry_cancellation_blocks_dispatch_before_its_install()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(70))?,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(71))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(b"cancellation dispatch basis".to_vec())?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let coordinator = MaintenanceCoordinator::new();
    let lease = crate::SnapshotLeaseId::new([73; 16])?;
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([90; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let lease_object = CatalogObject::new(b"immutable lease binding".to_vec())?.identity();
    let task = snapshot_lease_expiry_task(lease, scope, lease_object);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .expect("expiry task persists");
    let durable = coordinator
        .durable_records()
        .expect("durable records")
        .into_iter()
        .next()
        .expect("one durable expiry task");
    let cancellation = coordinator
        .prepare_snapshot_lease_expiry_cancellation(
            lease,
            scope,
            lease_object,
            7,
            10,
            durable.as_bytes(),
        )
        .expect("cancellation preparation")
        .expect("queued expiry task prepares cancellation");

    assert_eq!(
        coordinator
            .cancel_and_persist(&catalog, identity)
            .expect_err("a prepared cancellation owns the task transition"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator.status(identity).expect("queued task").phase(),
        MaintenanceTaskPhase::Queued
    );

    assert!(
        coordinator
            .start_next(10, false)
            .expect("scheduler admission")
            .is_none(),
        "the prepared cancellation retains the queued descriptor until publication resolves"
    );
    assert_eq!(
        coordinator.status(identity).expect("queued task").phase(),
        MaintenanceTaskPhase::Queued
    );

    cancellation
        .install(&coordinator)
        .expect("installation owns the same queued task");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("cancelled task")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    Ok(())
}

#[test]
fn prepared_running_lease_expiry_completion_blocks_cancellation_before_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(74))?,
        CatalogSecret::from_owned(Box::new([0x75; 32]), Box::new([0x76; 32])),
    )?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(75))?,
        FormatEpoch::CATALOG_V1,
        vec![CatalogObject::new(
            b"running completion dispatch basis".to_vec(),
        )?],
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;
    let coordinator = MaintenanceCoordinator::new();
    let lease = crate::SnapshotLeaseId::new([77; 16])?;
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([0x43; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let lease_object = CatalogObject::new(b"running immutable lease binding".to_vec())?.identity();
    let task = snapshot_lease_expiry_task(lease, scope, lease_object);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 1)
        .expect("expiry task persists");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 10, false)
        .expect("dispatch")
        .expect("due expiry execution");
    let durable = coordinator
        .durable_records()
        .expect("durable records")
        .into_iter()
        .next()
        .ok_or("running durable expiry task")?;
    let completion = execution
        .prepare_running_snapshot_lease_expiry_completion(
            &coordinator,
            SnapshotLeaseExpiryBinding::new(lease, scope, lease_object, 7, 10, durable.as_bytes()),
        )
        .expect("running completion preparation");

    assert_eq!(
        coordinator
            .cancel_and_persist(&catalog, identity)
            .expect_err("prepared completion owns the Running transition"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator.status(identity).expect("running task").phase(),
        MaintenanceTaskPhase::Running
    );
    assert_eq!(
        coordinator
            .checkpoint(
                identity,
                MaintenanceCheckpoint::new(1, 0, vec![1]).expect("checkpoint"),
            )
            .expect_err("prepared completion fences direct test-model checkpoints"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        coordinator
            .complete(identity, true)
            .expect_err("prepared completion fences direct test-model terminalization"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        execution
            .checkpoint_and_persist(
                &coordinator,
                &catalog,
                MaintenanceCheckpoint::new(1, 0, vec![1]).expect("checkpoint"),
            )
            .expect_err("prepared completion fences handler checkpoints"),
        MaintenanceFailure::PreconditionFailed
    );
    assert_eq!(
        execution
            .complete_and_persist(&coordinator, &catalog, true)
            .expect_err("prepared completion fences generic terminalization"),
        MaintenanceFailure::PreconditionFailed
    );
    coordinator.recover_after_crash().expect("crash recovery");
    assert!(
        coordinator
            .start_next(10, false)
            .expect("recovered scheduling")
            .is_some(),
        "crash recovery drops the prepared transition reservation"
    );
    completion
        .discard(&coordinator)
        .expect("discard prepared completion");
    coordinator
        .cancel_and_persist(&catalog, identity)
        .expect("cancellation after discarded completion");
    assert!(
        coordinator
            .status(identity)
            .expect("running cancellation")
            .cancellation_requested()
    );
    Ok(())
}

#[test]
fn ordinary_submissions_never_evict_a_terminal_reserved_for_lease_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let coordinator = MaintenanceCoordinator::new();
    let lease = crate::SnapshotLeaseId::new([74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        .expect("lease identity");
    let scope = MaintenanceScope::segment(
        TenantId::from_bytes([90; 16]).expect("tenant"),
        SignalKind::Logs,
        VirtualShardId::new(1).expect("shard"),
    );
    let lease_object = CatalogObject::new(b"reserved lease binding".to_vec())
        .expect("catalog object")
        .identity();
    let reserved = MaintenanceTaskId::new([1; 16]).expect("reserved task identity");
    {
        let mut state = coordinator.state.lock().expect("coordinator state");
        for raw in 1..=u8::try_from(MAX_MAINTENANCE_TASKS).expect("task count") {
            let task = catalog_task(raw);
            let identity = task.identity();
            state.tasks.insert(
                identity,
                TaskState {
                    task,
                    phase: MaintenanceTaskPhase::Cancelled,
                    submitted_at: u64::from(raw),
                    checkpoint: None,
                    pause_until: None,
                    cancellation_requested: false,
                    dispatches: 0,
                    terminal_order: Some(u64::from(raw)),
                    active_dispatch: None,
                },
            );
        }
        state.next_terminal_order = u64::from(MAX_MAINTENANCE_TASKS as u32) + 1;
    }
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(nonzero_id(75))?,
        CatalogSecret::from_owned(Box::new([0x76; 32]), Box::new([0x77; 32])),
    )?;
    let records = coordinator
        .durable_records()
        .expect("terminal records encode for catalog");
    let objects = records
        .into_iter()
        .map(|record| CatalogObject::new(record.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let initial = CatalogProposal::new(
        TransactionId::new(nonzero_id(76))?,
        FormatEpoch::CATALOG_V1,
        objects,
    )?;
    catalog.commit(catalog.pin()?.identity(), initial, None)?;

    let submission = coordinator
        .prepare_snapshot_lease_expiry(lease, scope, lease_object, 7, 10)
        .expect("lease publication reserves the oldest terminal");
    assert_eq!(submission.reclaimed_task_identity(), Some(reserved));

    let ordinary = catalog_task(200);
    coordinator
        .submit_at(ordinary.clone(), 11)
        .expect("another terminal is reclaimed for ordinary work");
    assert!(
        coordinator.status(reserved).is_ok(),
        "the lease draft still owns its selected terminal record"
    );
    assert!(coordinator.status(ordinary.identity()).is_ok());
    let persisted = catalog_task(201);
    coordinator
        .submit_and_persist(&catalog, persisted.clone(), 12)
        .expect("persistent submission reclaims a different terminal");
    assert!(
        coordinator.status(reserved).is_ok(),
        "persistent submission also preserves the lease draft's terminal"
    );
    assert!(coordinator.status(persisted.identity()).is_ok());
    submission
        .discard(&coordinator)
        .expect("discard lease submission");
    Ok(())
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
        MaintenanceTaskClass::SchemaStatistics,
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
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
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
        .start_next_with_reservation_and_persist(&reopened, &authority, 9, false)
        .expect("resumed dispatch admission")
        .expect("recovered task must dispatch");
    let failure =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            execution.complete_and_persist(&restored, &reopened, true)
        });
    assert_eq!(
        failure.expect_err("terminal publication must fail"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        restored.status(identity).expect("running status").phase(),
        MaintenanceTaskPhase::Running,
        "the retained execution can retry its exact terminal record"
    );
    execution
        .complete_and_persist(&restored, &reopened, true)
        .expect("terminal outcome must publish");
    assert_eq!(
        restored.status(identity).expect("terminal status").phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        execution
            .complete_and_persist(&restored, &reopened, true)
            .expect_err("a terminal execution cannot publish a second outcome"),
        MaintenanceFailure::InvalidTransition
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
        MaintenanceTaskClass::SchemaStatistics,
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

#[test]
fn catalog_dispatch_fault_keeps_work_queued_and_reopen_recovers_durable_running()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(21))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(22))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance dispatch basis".to_vec())?],
        )?,
        None,
    )?;

    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(44);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    let failure =
        crate::catalog::with_catalog_fault(crate::catalog::CatalogFileEvent::WriteMarker, || {
            coordinator.start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        });
    let Err(failure) = failure else {
        panic!("running publication must fail");
    };
    assert_eq!(failure, MaintenanceFailure::CatalogUnavailable);
    assert_eq!(
        coordinator.status(identity).expect("queued status").phase(),
        MaintenanceTaskPhase::Queued,
        "resource admission cannot make running state visible before Catalog publication"
    );

    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("retry admission")
        .expect("exact retry must reserve and publish running");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("running status")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    drop(execution);
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened).expect("restore");
    assert_eq!(
        restored.status(identity).expect("restored status").phase(),
        MaintenanceTaskPhase::Queued,
        "a process exit releases the in-memory reservation and resumes the durable checkpoint"
    );
    Ok(())
}

#[test]
fn catalog_pause_and_finite_window_survive_reopen_without_deferring_past_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(31))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x81; 32]), Box::new([0x82; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(32))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance controls basis".to_vec())?],
        )?,
        None,
    )?;

    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(45);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    coordinator
        .pause_and_persist(&catalog, identity, 9, 12, 8)
        .expect("pause must publish");
    coordinator
        .resume_and_persist(&catalog, identity)
        .expect("resume must publish");
    coordinator
        .set_window_and_persist(
            &catalog,
            [MaintenanceTaskClass::RepositoryVerification],
            20,
            9,
        )
        .expect("window must publish");
    drop(catalog);

    let reopened = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x81; 32]), Box::new([0x82; 32])),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&reopened).expect("restore");
    assert_eq!(
        restored.status(identity).expect("restored status").phase(),
        MaintenanceTaskPhase::Queued
    );
    assert!(
        restored
            .start_next_with_reservation_and_persist(&reopened, &authority, 19, false)
            .expect("window admission")
            .is_none(),
        "the persisted finite window defers only before its lifecycle expiry"
    );
    let execution = restored
        .start_next_with_reservation_and_persist(&reopened, &authority, 20, false)
        .expect("expiry admission")
        .expect("window expiry must make the queued task eligible");
    drop(execution);
    Ok(())
}

#[test]
fn catalog_post_publication_completion_ambiguity_retries_without_losing_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CatalogRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = crate::catalog::tests::support::establish_catalog_authority(volume)?;
    let instance = InstanceId::new(nonzero_id(41))?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x91; 32]), Box::new([0x92; 32])),
    )?;
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(nonzero_id(42))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(b"maintenance ambiguity basis".to_vec())?],
        )?,
        None,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let task = catalog_task(46);
    let identity = task.identity();
    coordinator
        .submit_and_persist(&catalog, task, 7)
        .expect("queued task must publish");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 8, false)
        .expect("dispatch admission")
        .expect("task must dispatch");

    let result = crate::catalog::with_catalog_fault(
        crate::catalog::CatalogFileEvent::SynchronizeGenerationDirectory,
        || execution.complete_and_persist(&coordinator, &catalog, true),
    );
    assert_eq!(
        result.expect_err("post-marker acknowledgement must be ambiguous"),
        MaintenanceFailure::CatalogUnavailable
    );
    assert_eq!(
        coordinator
            .status(identity)
            .expect("local running state")
            .phase(),
        MaintenanceTaskPhase::Running,
        "the retained execution is the sole retry capability until acknowledgement resolves"
    );
    execution
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("exact retry resolves the durable terminal publication");
    assert_eq!(
        coordinator
            .status(identity)
            .expect("terminal state")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}
