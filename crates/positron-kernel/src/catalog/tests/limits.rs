use super::super::{
    MAX_GENERATIONS, MAX_RETAINED_HISTORY_BYTES, audit_checkpoint_resource_claim,
    audit_reclamation_resource_claim, commit_resource_claim, reserve_history,
};
use crate::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSecret,
    CatalogWrappingKey, FormatEpoch, InstanceId, MaintenanceCoordinator, MaintenanceFailure,
    MaintenanceObjectId, MaintenancePreconditions, MaintenanceScope, MaintenanceTask,
    MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTaskPhase, MaintenanceTrigger,
    MountQualification, PrimaryDataVolume, ResourceAmounts, ResourceDimension, TransactionId,
};

use super::super::types::MAX_CATALOG_OBJECT_BYTES;
use super::super::{CatalogFailure, CatalogGenerationId};
use super::support::{establish_catalog_authority, establish_catalog_authority_with_repair_memory};

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_AUDIT_CHECKPOINT_CAPACITY_ROOT: AtomicU64 = AtomicU64::new(0);

struct AuditCheckpointCapacityRoot(PathBuf);

impl AuditCheckpointCapacityRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_AUDIT_CHECKPOINT_CAPACITY_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-audit-checkpoint-capacity-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for AuditCheckpointCapacityRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn audit_checkpoint_capacity_id(last: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[15] = last;
    bytes
}

#[test]
fn audit_reclamation_admission_reserves_one_real_frame_before_any_handler_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = audit_reclamation_resource_claim()?;
    assert_eq!(claim.get(ResourceDimension::MemoryBytes), 197_293);
    assert_eq!(claim.get(ResourceDimension::IoPermits), 1);
    assert_eq!(claim.get(ResourceDimension::CpuWorkUnits), 1);
    assert_eq!(claim.get(ResourceDimension::FileDescriptors), 1);

    let task = |id| {
        MaintenanceTask::with_contract(
            MaintenanceTaskId::new([id; 16]).expect("stable task identity"),
            MaintenanceTaskClass::CatalogReclamation,
            MaintenanceScope::System,
            MaintenanceTrigger::Event,
            MaintenancePreconditions::new(1, 1).expect("task preconditions"),
            vec![MaintenanceObjectId::new([id.wrapping_add(2); 32]).expect("task input")],
            vec![MaintenanceObjectId::new([id.wrapping_add(3); 32]).expect("task output")],
            claim,
        )
        .expect("source-derived task contract")
    };
    let below = claim
        .get(ResourceDimension::MemoryBytes)
        .checked_sub(1)
        .ok_or("nonzero real audit-frame claim")?;
    let root = AuditCheckpointCapacityRoot::new()?;
    let authority = establish_catalog_authority_with_repair_memory(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        below,
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let blocker = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xc0; 16]).expect("stable blocker identity"),
        MaintenanceTaskClass::CatalogReclamation,
        MaintenanceScope::System,
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(1, 1).expect("blocker preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([below + 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    )
    .expect("shared-capacity blocker contract");
    let blocker_identity = blocker.identity();
    coordinator
        .submit(blocker)
        .expect("queued shared-capacity blocker");
    let refused = task(0xc1);
    let refused_identity = refused.identity();
    coordinator.submit(refused).expect("queued audit reclaimer");
    let held = coordinator
        .start_next_with_reservation(&authority, 2, false)
        .expect("shared-capacity blocker admission")
        .ok_or("shared-capacity blocker execution")?;
    assert_eq!(held.task().identity(), blocker_identity);
    assert!(matches!(
        coordinator.start_next_with_reservation(&authority, 2, false),
        Err(MaintenanceFailure::ResourceAdmissionRefused)
    ));
    assert_eq!(
        coordinator
            .status(refused_identity)
            .expect("queued task status")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "refusal leaves the exact audit reclaimer queued before any handler can unlink a frame"
    );
    drop(held);

    let root = AuditCheckpointCapacityRoot::new()?;
    let authority = establish_catalog_authority_with_repair_memory(
        PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?,
        claim.get(ResourceDimension::MemoryBytes),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let admitted = task(0xc2);
    let identity = admitted.identity();
    coordinator
        .submit(admitted)
        .expect("queued audit reclaimer");
    let execution = coordinator
        .start_next_with_reservation(&authority, 2, false)
        .expect("source-derived claim admission")
        .ok_or("the source-derived claim admits one audit reclaimer")?;
    assert_eq!(execution.task().identity(), identity);
    assert_eq!(
        coordinator
            .status(identity)
            .expect("running task status")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    Ok(())
}

#[test]
fn audit_checkpoint_refuses_a_second_source_claim_while_the_first_is_held_then_releases_it()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = audit_checkpoint_resource_claim();
    let root = AuditCheckpointCapacityRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let authority = establish_catalog_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new(audit_checkpoint_capacity_id(91))?,
        CatalogSecret::from_owned(Box::new([0x91; 32]), Box::new([0x92; 32])),
    )?;
    let mut tasks = Vec::new();
    for (index, fingerprint) in [(92, 0xa1), (93, 0xa2)] {
        catalog.commit(
            catalog.pin()?.identity(),
            CatalogProposal::new(
                TransactionId::new(audit_checkpoint_capacity_id(index))?,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(
                    format!("audit checkpoint frontier {index}").into_bytes(),
                )?],
            )?,
            Some(AuditIntent::new(
                format!("action=audit-frontier-{index}").into_bytes(),
            )?),
        )?;
        let frontier = catalog
            .governance_audit_records()?
            .into_iter()
            .last()
            .ok_or("audit frontier")?;
        let (task, binding) =
            Catalog::governance_audit_checkpoint_task(&frontier, [fingerprint; 32])?;
        assert_eq!(task.reservations(), claim);
        tasks.push((task, binding));
    }
    let first_identity = tasks[0].0.identity();
    let second_identity = tasks[1].0.identity();
    let coordinator = MaintenanceCoordinator::new();
    for (now, (task, binding)) in (1_u64..).zip(tasks) {
        coordinator
            .submit_governance_audit_checkpoint_and_persist(&catalog, task, binding, now)
            .expect("audit task queues through the Catalog");
    }

    let first = coordinator
        .start_task_with_reservation_and_persist(&catalog, &authority, 3, false, first_identity)
        .expect("first source-derived audit task admission")
        .ok_or("first source-derived audit task must receive its exact grant")?;
    let before_refusal = catalog.pin()?;
    let before_refusal_generation = before_refusal.number();
    let before_refusal_task_records = before_refusal
        .plaintext_objects()
        .filter(|bytes| bytes.starts_with(b"PMTC"))
        .count();
    assert!(catalog.latest_audit_checkpoint()?.is_none());

    let refusal = match coordinator.start_task_with_reservation_and_persist(
        &catalog,
        &authority,
        4,
        false,
        second_identity,
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("the held first grant must leave insufficient durability capacity"),
    };
    assert_eq!(refusal, MaintenanceFailure::ResourceAdmissionRefused);
    assert_eq!(
        coordinator
            .status(second_identity)
            .expect("second task remains known")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "refused admission cannot expose a Running task state"
    );
    let after_refusal = catalog.pin()?;
    assert_eq!(after_refusal.number(), before_refusal_generation);
    assert_eq!(
        after_refusal
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        before_refusal_task_records,
        "refused admission cannot publish a task-record replacement"
    );
    assert!(catalog.latest_audit_checkpoint()?.is_none());

    first
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("the exact held grant covers the terminal Catalog proposal");
    drop(first);
    let second = coordinator
        .start_task_with_reservation_and_persist(&catalog, &authority, 5, false, second_identity)
        .expect("released capacity retries source-derived audit admission")
        .ok_or("releasing the held grant must admit the same source-derived claim")?;
    second
        .complete_and_persist(&coordinator, &catalog, true)
        .expect("the released exact grant covers the second terminal Catalog proposal");
    assert_eq!(
        coordinator
            .status(first_identity)
            .expect("first task state")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        coordinator
            .status(second_identity)
            .expect("second task state")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    drop(second);

    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(audit_checkpoint_capacity_id(94))?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(
                b"admitted writer defensive frontier".to_vec(),
            )?],
        )?,
        Some(AuditIntent::new(
            b"action=admitted-writer-defensive-frontier".to_vec(),
        )?),
    )?;
    let frontier = catalog
        .governance_audit_records()?
        .into_iter()
        .last()
        .ok_or("admitted writer frontier")?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(vec![0xa5; MAX_CATALOG_OBJECT_BYTES])?);
    let proposal = CatalogProposal::new(
        TransactionId::new(audit_checkpoint_capacity_id(95))?,
        basis
            .format_epoch()
            .ok_or("Catalog basis must carry a writable format epoch")?,
        objects,
    )?;
    let required = commit_resource_claim(&proposal, None)?;
    assert!(
        ResourceDimension::ALL
            .iter()
            .all(|dimension| claim.get(*dimension) >= required.get(*dimension)),
        "the canonical checkpoint claim must cover every source-derived terminal proposal dimension"
    );
    let underclaimed = ResourceAmounts::new([
        required.get(ResourceDimension::MemoryBytes),
        required.get(ResourceDimension::QueueSlots),
        required.get(ResourceDimension::TaskSlots),
        required.get(ResourceDimension::BufferCacheBytes),
        required.get(ResourceDimension::BatchItems),
        required.get(ResourceDimension::LeaseSlots),
        required.get(ResourceDimension::RetrySlots),
        required.get(ResourceDimension::IoPermits),
        required.get(ResourceDimension::CpuWorkUnits),
        required.get(ResourceDimension::FileDescriptors),
        required
            .get(ResourceDimension::DiskHeadroomBytes)
            .checked_sub(1)
            .ok_or("the real proposal must charge durable headroom")?,
    ]);
    assert_eq!(
        underclaimed.get(ResourceDimension::DiskHeadroomBytes),
        required.get(ResourceDimension::DiskHeadroomBytes) - 1,
        "the real task deliberately holds one fewer source-derived durable byte"
    );
    let underclaimed_task = MaintenanceTask::with_contract(
        MaintenanceTaskId::new([0xb1; 16]).expect("stable defensive task identity"),
        MaintenanceTaskClass::GovernanceAuditCheckpoint,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(frontier.position(), 1)
            .expect("frontier-derived task preconditions"),
        vec![
            MaintenanceObjectId::new(frontier.record_hash())
                .expect("audit frontier hash is a maintenance object identity"),
        ],
        vec![
            MaintenanceObjectId::new([0xb2; 32])
                .expect("integrity fingerprint is a maintenance object identity"),
        ],
        underclaimed,
    )
    .expect("one-byte-below actual proposal claim remains a valid task contract");
    let underclaimed_identity = underclaimed_task.identity();
    let underclaimed_binding = crate::GovernanceAuditCheckpointBinding::new(
        frontier.position(),
        frontier.record_hash(),
        [0xb2; 32],
    )
    .expect("nonzero audit checkpoint binding");
    coordinator
        .submit_governance_audit_checkpoint_and_persist(
            &catalog,
            underclaimed_task,
            underclaimed_binding,
            6,
        )
        .expect("the real governor can admit the source-derived one-byte-under task contract");
    let execution = coordinator
        .start_task_with_reservation_and_persist(
            &catalog,
            &authority,
            7,
            false,
            underclaimed_identity,
        )
        .expect("the real governor admits the deliberately underdeclared task")
        .ok_or("underclaimed task execution")?;
    let writer_basis = catalog.pin()?;
    let generation_before_writer_refusal = writer_basis.number();
    let writer_refusal = catalog
        .commit_admitted_maintenance_task_state(writer_basis.identity(), proposal, &execution)
        .expect_err("the admitted writer must reject the one-byte-under real proposal claim");
    assert_eq!(
        writer_refusal.code(),
        CatalogFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(
        catalog.pin()?.number(),
        generation_before_writer_refusal,
        "writer rejection cannot publish a Catalog generation"
    );
    assert_eq!(
        coordinator
            .status(underclaimed_identity)
            .expect("underclaimed task state")
            .phase(),
        MaintenanceTaskPhase::Running,
        "writer rejection cannot mutate the coordinator terminal state"
    );
    assert!(catalog.latest_audit_checkpoint()?.is_none());
    drop(execution);
    Ok(())
}

#[test]
fn retained_history_admits_the_exact_boundary_and_refuses_the_next_byte() {
    assert_eq!(
        reserve_history(MAX_RETAINED_HISTORY_BYTES - 1, 1, 1)
            .expect("the exact retained-history boundary must remain recoverable"),
        MAX_RETAINED_HISTORY_BYTES
    );
    assert_eq!(
        reserve_history(MAX_RETAINED_HISTORY_BYTES, 1, 1)
            .expect_err("one byte beyond recoverable history must be refused")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
    assert_eq!(
        reserve_history(0, 1, MAX_GENERATIONS as u64 + 1)
            .expect_err("one generation beyond the recoverable bound must be refused")
            .code(),
        CatalogFailureCode::LimitExceeded
    );
}

#[test]
fn root_key_routing_requires_nonzero_provider_and_epoch() {
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [0; 16], 1)
            .expect_err("the zero provider reference is reserved")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [1; 16], 0)
            .expect_err("the zero root-key epoch is reserved")
            .code(),
        CatalogFailureCode::InvalidInput
    );
    assert_eq!(
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [0; 16], 1,)
            .expect_err("the explicit marker authority does not weaken routing validation")
            .code(),
        CatalogFailureCode::InvalidInput
    );

    let current =
        CatalogSecret::from_owned_at_epoch(Box::new([2; 32]), Box::new([1; 32]), [1; 16], 2)
            .expect("current route is valid");
    let non_predecessor = CatalogWrappingKey::from_owned_at_epoch(Box::new([2; 32]), [2; 16], 2)
        .expect("candidate route is valid");
    assert_eq!(
        current
            .with_predecessor(non_predecessor)
            .expect_err("a predecessor epoch must be older")
            .code(),
        CatalogFailureCode::InvalidInput
    );

    let wrapping = CatalogWrappingKey::from_owned_at_epoch(Box::new([3; 32]), [3; 16], 3)
        .expect("wrapping route is valid");
    assert_eq!(format!("{wrapping:?}"), "CatalogWrappingKey { <redacted> }");

    let stale = CatalogFailure::stale(CatalogGenerationId::ORIGIN);
    assert_eq!(stale.code(), CatalogFailureCode::StaleGeneration);
    assert_eq!(
        stale.current_generation(),
        Some(CatalogGenerationId::ORIGIN)
    );
}

#[test]
fn opaque_digest_is_domain_separated_and_refuses_an_ambiguous_input() {
    let secret = CatalogSecret::from_owned(Box::new([0x71; 32]), Box::new([0x72; 32]));
    let first = secret
        .opaque_digest(b"positron.test.binding.v1\0", b"first")
        .expect("bounded binding input is accepted");
    let same = secret
        .opaque_digest(b"positron.test.binding.v1\0", b"first")
        .expect("same binding input is stable");
    let different_domain = secret
        .opaque_digest(b"positron.test.other.v1\0", b"first")
        .expect("different domain is accepted");
    let first_split = secret
        .opaque_digest(b"a", b"bc")
        .expect("first split binding is accepted");
    let second_split = secret
        .opaque_digest(b"ab", b"c")
        .expect("second split binding is accepted");
    assert_eq!(first, same);
    assert_ne!(first, different_domain);
    assert_ne!(first_split, second_split);
    assert_eq!(
        secret
            .opaque_digest(b"", b"first")
            .expect_err("an unscoped private binding is ambiguous")
            .code(),
        CatalogFailureCode::InvalidInput
    );
}
