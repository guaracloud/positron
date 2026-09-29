use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::super::support::{TemporaryRoot, establish_authority};
use crate::catalog::{CatalogFileEvent, with_catalog_fault};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, MaintenanceCoordinator,
    MaintenanceTaskId, MaintenanceTaskPhase, MountQualification, SegmentProtectionKey,
    SegmentScope, SnapshotLeaseId,
};

#[test]
fn dispatched_lease_expiry_removes_the_lease_and_succeeds_its_exact_task_atomically()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new().expect("temporary root");
    let volume = crate::PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)
        .expect("primary volume");
    let authority = establish_authority(volume).expect("kernel authority");
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16]).expect("instance id"),
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )
    .expect("catalog");
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16]).expect("tenant id"),
        SignalKind::Logs,
        VirtualShardId::new(1).expect("shard id"),
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
    )
    .expect("ledger");
    let coordinator = MaintenanceCoordinator::new();
    let basis = catalog.pin().expect("catalog basis");
    let lease = ledger
        .create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            100,
            std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
            basis.identity(),
        )
        .expect("lease and task publication");
    let identity = lease.identity();
    drop(lease);
    let task = MaintenanceTaskId::new(identity.to_bytes()).expect("lease id is a task id");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 150, false)
        .expect("scheduler dispatch")
        .expect("expiry task is due");

    ledger
        .complete_running_snapshot_lease_expiry_task(&coordinator, &execution, identity)
        .expect("atomic expiry completion");

    assert!(
        super::super::super::snapshot_lease::records(&catalog.pin()?)?
            .iter()
            .all(|record| record.identity != identity),
        "the lease removal shares the terminal task publication"
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1,
        "only the exact terminal expiry record remains"
    );
    assert_eq!(
        coordinator.status(task).expect("terminal task").phase(),
        MaintenanceTaskPhase::Succeeded
    );
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    assert_eq!(
        restored
            .status(task)
            .expect("restored terminal task")
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "the durable task outcome and lease removal reopen consistently"
    );
    Ok(())
}

#[test]
fn running_expiry_execution_rejects_a_foreign_lease_without_terminalizing_its_task()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = crate::PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
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
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let task = MaintenanceTaskId::new(lease.identity().to_bytes()).expect("lease task id");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 150, false)
        .expect("dispatch")
        .expect("due expiry");
    let foreign = SnapshotLeaseId::new([0xfe; 16])?;

    let failure = ledger
        .complete_running_snapshot_lease_expiry_task(&coordinator, &execution, foreign)
        .expect_err("a dispatch cannot terminalize another lease");
    assert_eq!(failure.code(), crate::LedgerFailureCode::StaleGeneration);
    assert_eq!(
        coordinator.status(task).expect("running task").phase(),
        MaintenanceTaskPhase::Running
    );
    assert!(
        super::super::super::snapshot_lease::records(&catalog.pin()?)?
            .iter()
            .any(|record| record.identity == lease.identity())
    );
    Ok(())
}

#[test]
fn failed_running_expiry_publication_keeps_its_execution_for_the_exact_retry()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = crate::PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xc1; 16])?,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
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
        SegmentProtectionKey::from_owned(Box::new([0xc4; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(50).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let identity = lease.identity();
    let task = MaintenanceTaskId::new(identity.to_bytes()).expect("lease task id");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 150, false)
        .expect("dispatch")
        .expect("due expiry");

    let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
        ledger.complete_running_snapshot_lease_expiry_task(&coordinator, &execution, identity)
    })
    .expect_err("a failed catalog proposal cannot complete the execution");
    assert_eq!(failure.code(), crate::LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        coordinator.status(task).expect("retained task").phase(),
        MaintenanceTaskPhase::Running,
        "the same execution retains its reservation for the retry"
    );
    assert!(
        super::super::super::snapshot_lease::records(&catalog.pin()?)?
            .iter()
            .any(|record| record.identity == identity)
    );

    ledger.complete_running_snapshot_lease_expiry_task(&coordinator, &execution, identity)?;
    assert_eq!(
        coordinator.status(task).expect("terminal task").phase(),
        MaintenanceTaskPhase::Succeeded
    );
    Ok(())
}
