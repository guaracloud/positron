use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::fault::{LedgerFileEvent, with_ledger_errno, with_ledger_fault};
use crate::catalog::{CatalogFileEvent, with_catalog_fault, with_catalog_fault_hook_after};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch,
    InstanceId, LedgerCompletionState, LedgerFailureCode, MaintenanceCoordinator,
    MaintenanceTaskId, MaintenanceTaskPhase, MountQualification, PreparedStoreBlock,
    PrimaryDataVolume, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, TransactionId,
    WorkClaim, WorkKind,
};

mod admission_faults;
mod coupled_lease_capacity;
mod coupled_lease_lifecycle;
mod sealing_faults;
mod snapshot_lease_capacity;
mod snapshot_leases;

#[test]
fn lease_expiry_task_is_published_with_its_lease_and_waits_for_its_due_time()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let basis = catalog.pin()?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
        basis.identity(),
    )?;
    let task =
        MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease identity is valid");
    assert_eq!(
        coordinator.status(task).expect("task is installed").phase(),
        MaintenanceTaskPhase::Queued,
        "the in-memory coordinator installs only after the coupled Catalog commit"
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1,
        "the immutable lease and exactly one expiry descriptor are co-present"
    );
    assert!(
        coordinator
            .start_next_with_reservation_and_persist(&catalog, &authority, 149, false)
            .expect("scheduler checks due time")
            .is_none()
    );
    assert!(
        coordinator
            .start_next_with_reservation_and_persist(&catalog, &authority, 150, true)
            .expect("uncertain clock blocks scheduled expiry")
            .is_none()
    );
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 150, false)
        .expect("scheduler admits due work")
        .ok_or("due expiry task must dispatch")?;
    assert_eq!(execution.task().identity(), task);
    Ok(())
}

#[test]
fn lease_expiry_publication_fault_never_leaves_only_a_lease_or_only_a_task()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x41; 16])?,
        CatalogSecret::from_owned(Box::new([0x42; 32]), Box::new([0x43; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let protection = || SegmentProtectionKey::from_owned(Box::new([0x44; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, protection())?;
    let coordinator = MaintenanceCoordinator::new();
    let basis = catalog.pin()?;
    let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
        ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            100,
            std::num::NonZeroU64::new(50).expect("nonzero ttl"),
            basis.identity(),
        )
    })
    .expect_err("faulted transaction must not publish either member");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        0
    );
    assert!(super::super::snapshot_lease::records(&catalog.pin()?)?.is_empty());

    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let identity = lease.identity();
    drop(lease);
    drop(ledger);
    drop(coordinator);
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        protection(),
        &crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(UnixNanoseconds::new(
            101_000_000_000,
        ))),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .expect("the co-published task must survive reopen");
    assert_eq!(
        restored
            .status(MaintenanceTaskId::new(identity.to_bytes()).expect("valid identity"))
            .expect("co-published task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    drop(reopened.resume_snapshot_lease(identity, 101)?);
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1,
        "retry creates exactly one coupled task"
    );
    Ok(())
}

#[test]
fn refused_coupled_lease_publication_discards_its_unpublished_task_draft()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x46; 16])?,
        CatalogSecret::from_owned(Box::new([0x47; 32]), Box::new([0x48; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x49; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let held = authority.governor().reserve(WorkClaim::tenant(
        scope.tenant,
        WorkKind::InteractiveQueryTail,
        crate::ResourceAmounts::only(crate::ResourceDimension::LeaseSlots, 16)?,
    )?)?;

    for now in 100..=228 {
        assert_eq!(
            ledger
                .create_snapshot_lease_for_at_catalog_with_expiry_task(
                    &coordinator,
                    now,
                    std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
                    catalog.pin()?.identity(),
                )
                .expect_err("saturated lease capacity must refuse publication")
                .code(),
            LedgerFailureCode::ResourceAdmissionRefused
        );
    }
    assert!(super::super::snapshot_lease::records(&catalog.pin()?)?.is_empty());
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        0
    );

    drop(held);
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        229,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    assert!(
        coordinator
            .status(
                MaintenanceTaskId::new(lease.identity().to_bytes())
                    .expect("lease identity is a valid maintenance identity"),
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn ambiguous_coupled_publication_retries_lease_and_descriptor_as_one_pair()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x4a; 16])?,
        CatalogSecret::from_owned(Box::new([0x4b; 32]), Box::new([0x4c; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x4d; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let failure = with_ledger_fault(LedgerFileEvent::BeforeLeaseCreationReconciliation, || {
        ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            100,
            std::num::NonZeroU64::new(50).expect("nonzero ttl"),
            catalog.pin().expect("catalog basis").identity(),
        )
    })
    .expect_err("post-commit uncertainty remains typed until pair reconciliation");
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    catalog.refresh_state()?;

    let stale_basis = catalog.pin()?.identity();
    assert_eq!(
        ledger
            .create_snapshot_lease_for_at_catalog_with_expiry_task(
                &coordinator,
                101,
                std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
                stale_basis,
            )
            .expect_err("cleanup advances the generation that admission was bound to")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    let retry = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        101,
        std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    assert_eq!(
        super::super::snapshot_lease::records(&catalog.pin()?)?.len(),
        1,
        "retry leaves one live lease"
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1,
        "retry removes the descriptor paired with the abandoned lease"
    );
    assert!(
        coordinator
            .status(MaintenanceTaskId::new(retry.identity().to_bytes()).expect("task identity"))
            .is_ok()
    );
    Ok(())
}

#[test]
fn lease_expiry_marker_acknowledgement_ambiguity_reconciles_the_coupled_generation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x51; 16])?,
        CatalogSecret::from_owned(Box::new([0x52; 32]), Box::new([0x53; 32])),
    )?;
    let unrelated = CatalogObject::new(b"unrelated lease basis".to_vec())?;
    let unrelated_id = unrelated.identity();
    catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new([0x54; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![unrelated],
        )?,
        None,
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let protection = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, protection())?;
    let coordinator = MaintenanceCoordinator::new();
    let basis = catalog.pin()?;
    let lease = with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
        ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            100,
            std::num::NonZeroU64::new(50).expect("nonzero ttl"),
            basis.identity(),
        )
    })
    .expect("the publisher reconciles a visible generation after acknowledgement ambiguity");
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("valid task identity");
    assert_eq!(
        coordinator
            .status(task)
            .expect("post-commit install")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    let snapshot = catalog.pin()?;
    assert_eq!(
        snapshot.object(unrelated_id)?,
        Some(b"unrelated lease basis".as_slice())
    );
    assert_eq!(
        snapshot
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1
    );
    assert_eq!(super::super::snapshot_lease::records(&snapshot)?.len(), 1);
    drop((lease, ledger, coordinator));
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        protection(),
        &crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(UnixNanoseconds::new(
            101_000_000_000,
        ))),
    )?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .expect("reopen restores the co-published task");
    assert_eq!(
        restored.status(task).expect("durable task").phase(),
        MaintenanceTaskPhase::Queued
    );
    drop(reopened);
    Ok(())
}

#[test]
fn coupled_lease_replacement_reconciles_marker_acknowledgement_ambiguity()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x56; 16])?,
        CatalogSecret::from_owned(Box::new([0x57; 32]), Box::new([0x58; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let protection = || SegmentProtectionKey::from_owned(Box::new([0x59; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, protection())?;
    let coordinator = MaintenanceCoordinator::new();
    ledger.append(prepared(scope, b"leased")?)?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let old_identity = lease.identity();
    drop(lease);
    ledger.append(prepared(scope, b"newer")?)?;
    let replacement_basis = catalog.pin()?;
    let expected_catalog_identity = replacement_basis.identity();
    let expected_catalog_generation = replacement_basis.number();
    let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 101, 200)?;
    let new_identity = replacement.identity();
    let grant = with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
        replacement.commit_with_expiry_task(&coordinator)
    })
    .expect("visible replacement must reconcile acknowledgement ambiguity");
    assert_eq!(grant.identity(), new_identity);
    assert_eq!(
        grant.snapshot().catalog_identity(),
        expected_catalog_identity
    );
    assert_eq!(
        grant.snapshot().catalog_generation(),
        expected_catalog_generation
    );
    drop(grant);
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new(old_identity.to_bytes()).expect("task identity"))
            .expect("old task status")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new(new_identity.to_bytes()).expect("task identity"))
            .expect("new task status")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    let snapshot = catalog.pin()?;
    assert_eq!(super::super::snapshot_lease::records(&snapshot)?.len(), 1);
    assert_eq!(
        snapshot
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        2,
        "the cancelled old descriptor and queued replacement survive together"
    );
    drop(replacement);
    drop(ledger);
    drop(coordinator);
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    assert_eq!(
        restored
            .status(MaintenanceTaskId::new(old_identity.to_bytes()).expect("task identity"))
            .expect("old restored task")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert_eq!(
        restored
            .status(MaintenanceTaskId::new(new_identity.to_bytes()).expect("task identity"))
            .expect("new restored task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        protection(),
        &crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(UnixNanoseconds::new(
            101_000_000_000,
        ))),
    )?;
    drop(reopened.resume_snapshot_lease(new_identity, 101)?);
    assert_eq!(
        reopened
            .resume_snapshot_lease(old_identity, 101)
            .expect_err("replacement atomically retires its old lease")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn faulted_coupled_lease_replacement_preserves_old_lease_and_expiry_task()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x5a; 16])?,
        CatalogSecret::from_owned(Box::new([0x5b; 32]), Box::new([0x5c; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    ledger.append(prepared(scope, b"leased")?)?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let old_identity = lease.identity();
    drop(lease);
    ledger.append(prepared(scope, b"newer")?)?;
    let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 101, 200)?;
    let new_identity = replacement.identity();
    let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
        replacement.commit_with_expiry_task(&coordinator)
    })
    .expect_err("a pre-commit fault must leave the old pair authoritative");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    drop(replacement);
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new(old_identity.to_bytes()).expect("task identity"))
            .expect("old task remains installed")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    assert!(
        coordinator
            .status(MaintenanceTaskId::new(new_identity.to_bytes()).expect("task identity"))
            .is_err(),
        "an unpublished replacement task never reaches coordinator memory"
    );
    assert_eq!(
        super::super::snapshot_lease::records(&catalog.pin()?)?.len(),
        1
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1
    );
    drop(ledger.resume_snapshot_lease(old_identity, 101)?);
    Ok(())
}

fn prepared(
    scope: SegmentScope,
    payload: &[u8],
) -> Result<PreparedStoreBlock<'static>, crate::LedgerFailure> {
    let marker = payload.first().copied().unwrap_or(1).max(1);
    PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([marker; 16])?,
        payload.to_vec(),
    )
}

#[test]
fn failed_frame_synchronization_never_acknowledges_and_recovery_discards_its_tail()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let wrapping_key = || SegmentProtectionKey::from_owned(Box::new([0x65; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let acknowledged = ledger.append(prepared(scope, b"acknowledged")?)?;

    let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrame, || {
        ledger.append(prepared(scope, b"unacknowledged")?)
    })
    .expect_err("frame synchronization failure cannot return a receipt");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    assert_eq!(
        ledger
            .append(prepared(scope, b"must-reopen")?)
            .expect_err("a possibly mutated live segment is poisoned")
            .code(),
        LedgerFailureCode::RecoveryRequired
    );
    let snapshot_failure = match ledger.snapshot() {
        Ok(_) => return Err("post-mutation append uncertainty did not fence snapshots".into()),
        Err(failure) => failure,
    };
    assert_eq!(snapshot_failure.code(), LedgerFailureCode::RecoveryRequired);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    assert_eq!(reopened.snapshot()?.frontier(), acknowledged.position());
    assert_eq!(reopened.snapshot()?.blocks().len(), 1);
    assert_eq!(reopened.snapshot()?.blocks()[0].payload(), b"acknowledged");
    Ok(())
}

#[test]
fn preparation_capacity_is_consumed_by_the_admitted_append() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
        )?;
        let payload = b"pre-admitted preparation";
        let amounts = super::super::capacity::append_claim(payload.len())?;
        let capacity = authority.governor().reserve(
            WorkClaim::tenant(scope.tenant, WorkKind::Ingest, amounts).expect("valid ingest claim"),
        )?;
        let block = PreparedStoreBlock::new_with_preparation_capacity(
            scope,
            StoreBlockIdentity::new([0x74; 16])?,
            payload.to_vec(),
            capacity,
        )?;

        let receipt = ledger.append(block)?;
        assert_eq!(receipt.position().value(), 1);
        assert_eq!(ledger.snapshot()?.blocks()[0].payload(), payload);
        Ok(())
    })
}

#[test]
fn recovery_discards_a_partial_first_frame_without_a_frontier() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let failure = with_ledger_fault(LedgerFileEvent::PartialFrameWrite, || {
            ledger.append(prepared(scope, b"partial-first")?)
        })
        .expect_err("partial first frame cannot publish a frontier");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        drop(ledger);

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.frontier().value(), 0);
        assert!(reopened.snapshot()?.blocks().is_empty());
        Ok(())
    })
}

#[test]
fn repeated_empty_seals_and_an_interrupted_successor_append_remain_restartable()
-> Result<(), Box<dyn Error>> {
    for _ in 0..8 {
        with_fixture(|authority, catalog, scope| {
            let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));

            ActiveSegmentLedger::open(authority, catalog, scope, key())?.seal()?;
            ActiveSegmentLedger::open(authority, catalog, scope, key())?.seal()?;

            let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let acknowledged =
                ledger.append(prepared(scope, b"acknowledged-after-empty-seals")?)?;
            drop(ledger);

            let recovered = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrame, || {
                recovered.append(prepared(scope, b"interrupted-successor")?)
            })
            .expect_err("an interrupted successor append cannot acknowledge");
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RecoveryRequired
            );
            drop(recovered);

            let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let snapshot = reopened.snapshot()?;
            assert_eq!(snapshot.frontier(), acknowledged.position());
            assert_eq!(snapshot.blocks().len(), 1);
            assert_eq!(
                snapshot.blocks()[0].payload(),
                b"acknowledged-after-empty-seals"
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn append_fault_matrix_never_overstates_the_authenticated_frontier() -> Result<(), Box<dyn Error>> {
    let before_frontier = [
        (
            LedgerFileEvent::WriteFrame,
            LedgerCompletionState::RejectedBeforeMutation,
        ),
        (
            LedgerFileEvent::PartialFrameWrite,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::SynchronizeFrame,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::InspectSegmentMetadata,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::RemoveFrontierTemporary,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::CreateFrontierTemporary,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::WriteFrontier,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::PartialFrontierWrite,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::SynchronizeFrontier,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::RenameFrontier,
            LedgerCompletionState::RecoveryRequired,
        ),
    ];
    for (event, completion) in before_frontier {
        with_fixture(|authority, catalog, scope| {
            let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
            let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let first = ledger.append(prepared(scope, b"first")?)?;
            let failure = with_ledger_fault(event, || ledger.append(prepared(scope, b"second")?))
                .expect_err("injected boundary cannot acknowledge");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            assert_eq!(failure.completion_state(), completion);
            if completion == LedgerCompletionState::RecoveryRequired {
                let append_failure = ledger
                    .append(prepared(scope, b"blocked-append")?)
                    .expect_err("a mutated segment refuses another append until reopen");
                assert_eq!(append_failure.code(), LedgerFailureCode::RecoveryRequired);
                let seal_failure = ledger
                    .seal()
                    .expect_err("a mutated segment refuses sealing until reopen");
                assert_eq!(seal_failure.code(), LedgerFailureCode::RecoveryRequired);
            } else {
                drop(ledger);
            }

            let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            assert_eq!(reopened.snapshot()?.frontier(), first.position());
            assert_eq!(reopened.snapshot()?.blocks().len(), 1);
            let retried = reopened.append(prepared(scope, b"second")?)?;
            assert_eq!(retried.position().value(), first.position().value() + 1);
            assert_eq!(reopened.snapshot()?.blocks().len(), 2);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn pre_write_refusal_keeps_the_live_ledger_retryable_without_nonce_reuse()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let failure = with_ledger_fault(LedgerFileEvent::WriteFrame, || {
            ledger.append(prepared(scope, b"retry-in-place")?)
        })
        .expect_err("pre-write fault cannot acknowledge");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );
        let committed = ledger.append(prepared(scope, b"retry-in-place")?)?;
        assert_eq!(committed.position().value(), 1);
        assert_eq!(ledger.snapshot()?.blocks().len(), 1);
        Ok(())
    })
}

#[test]
fn frontier_directory_sync_failure_is_typed_as_commit_ambiguity() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        ledger.append(prepared(scope, b"first")?)?;
        let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrontierDirectory, || {
            ledger.append(prepared(scope, b"ambiguous")?)
        })
        .expect_err("directory synchronization cannot acknowledge");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::CommitAmbiguous
        );
        assert_eq!(
            ledger
                .append(prepared(scope, b"blocked-after-ambiguity")?)
                .expect_err("an ambiguous append must refuse further mutation")
                .code(),
            LedgerFailureCode::RecoveryRequired
        );
        let seal_failure = with_ledger_fault(LedgerFileEvent::RenameSealSegment, || ledger.seal())
            .expect_err("an ambiguous append must be recovered before sealing");
        assert_eq!(seal_failure.code(), LedgerFailureCode::RecoveryRequired);
        assert_eq!(
            seal_failure.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.blocks().len(), 2);
        assert_eq!(reopened.snapshot()?.blocks()[1].payload(), b"ambiguous");
        Ok(())
    })
}

#[test]
fn full_disk_is_a_stable_typed_failure_without_a_receipt() -> Result<(), Box<dyn Error>> {
    for error in [rustix::io::Errno::NOSPC, rustix::io::Errno::DQUOT] {
        with_fixture(|authority, catalog, scope| {
            let ledger = ActiveSegmentLedger::open(
                authority,
                catalog,
                scope,
                SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
            )?;
            let failure = with_ledger_errno(LedgerFileEvent::WriteFrame, error, || {
                ledger.append(prepared(scope, b"no-space")?)
            })
            .expect_err("exhausted storage cannot acknowledge");
            assert_eq!(failure.code(), LedgerFailureCode::StorageExhausted);
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RejectedBeforeMutation
            );
            assert_eq!(ledger.snapshot()?.blocks().len(), 0);
            assert_eq!(
                ledger
                    .append(prepared(scope, b"no-space")?)?
                    .position()
                    .value(),
                1
            );
            Ok(())
        })?;
    }
    Ok(())
}

fn with_fixture<T>(
    action: impl FnOnce(
        &crate::StorageKernelResourceAuthority,
        &Catalog<'_>,
        SegmentScope,
    ) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    action(&authority, &catalog, scope)
}
