use super::*;

#[test]
fn expected_catalog_admission_rechecks_after_pending_release_cleanup() -> Result<(), Box<dyn Error>>
{
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
    let initial_catalog = catalog.pin()?.identity();
    let first = with_ledger_fault(LedgerFileEvent::BeforeLeaseCreationReconciliation, || {
        ledger.create_snapshot_lease_at_catalog(100, 200, initial_catalog)
    })
    .expect_err("post-publication uncertainty leaves its visible lease owned by cleanup");
    assert_eq!(
        first.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    let expected_catalog = catalog.pin()?.identity();
    assert_eq!(
        super::super::super::snapshot_lease::records(&catalog.pin()?)?.len(),
        1
    );

    let admission = ledger
        .create_snapshot_lease_at_catalog(101, 201, expected_catalog)
        .expect_err("cleanup publishes a newer catalog before the admission can commit");
    assert_eq!(admission.code(), LedgerFailureCode::StaleGeneration);
    assert!(super::super::super::snapshot_lease::records(&catalog.pin()?)?.is_empty());
    Ok(())
}

#[test]
fn creating_a_lease_terminalizes_the_expired_lease_expiry_task_before_installing_the_new_pair()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x4e; 16])?,
        CatalogSecret::from_owned(Box::new([0x4f; 32]), Box::new([0x50; 32])),
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
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let first = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(1).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let first_task =
        MaintenanceTaskId::new(first.identity().to_bytes()).expect("valid first task identity");
    drop(first);

    let second = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        101,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let second_task =
        MaintenanceTaskId::new(second.identity().to_bytes()).expect("valid second task identity");
    assert_eq!(
        coordinator.status(first_task).expect("first task").phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert_eq!(
        coordinator
            .status(second_task)
            .expect("second task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    let snapshot = catalog.pin()?;
    assert_eq!(
        super::super::super::snapshot_lease::records(&snapshot)?.len(),
        1
    );
    assert_eq!(
        snapshot
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn coupled_lease_release_reconciles_lost_acknowledgement_before_memory_cleanup()
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
    let baseline = authority.governor().inspect()?;
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let identity = lease.identity();
    let task = MaintenanceTaskId::new(identity.to_bytes()).expect("valid task identity");
    drop(lease);

    let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
        ledger.release_snapshot_lease_with_expiry_task(&coordinator, identity)
    })
    .expect_err("a pre-commit release fault leaves the expiry task schedulable");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        coordinator
            .status(task)
            .expect("queued task after fault")
            .phase(),
        MaintenanceTaskPhase::Queued
    );

    with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
        ledger.release_snapshot_lease_with_expiry_task(&coordinator, identity)
    })
    .expect("visible cancelled task reconciles an acknowledgement lost after commit");
    assert_eq!(
        coordinator.status(task).expect("cancelled task").phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert!(super::super::super::snapshot_lease::records(&catalog.pin()?)?.is_empty());
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        1
    );
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline.outstanding_total()
    );
    ledger.release_snapshot_lease_with_expiry_task(&coordinator, identity)?;
    assert_eq!(
        coordinator.status(task).expect("retry task").phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert_eq!(
        ledger
            .resume_snapshot_lease(identity, 101)
            .expect_err("released lease absent")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn coupled_lease_release_rejects_a_stale_expiry_descriptor() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x5e; 16])?,
        CatalogSecret::from_owned(Box::new([0x5f; 32]), Box::new([0x60; 32])),
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
        SegmentProtectionKey::from_owned(Box::new([0x61; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let identity = lease.identity();
    let task = MaintenanceTaskId::new(identity.to_bytes()).expect("valid task identity");
    drop(lease);

    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .filter(|bytes| !bytes.starts_with(b"PMTC"))
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut stale = basis
        .plaintext_objects()
        .find(|bytes| bytes.starts_with(b"PMTC"))
        .ok_or("coupled expiry descriptor")?
        .to_vec();
    stale[66..74].copy_from_slice(&101_u64.to_be_bytes());
    objects.push(CatalogObject::new(stale)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x62; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        ledger
            .release_snapshot_lease_with_expiry_task(&coordinator, identity)
            .expect_err("stale deadline cannot authorize release")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    assert_eq!(
        coordinator.status(task).expect("original task").phase(),
        MaintenanceTaskPhase::Queued
    );
    assert_eq!(
        super::super::super::snapshot_lease::records(&catalog.pin()?)?.len(),
        1
    );
    Ok(())
}

#[test]
fn coupled_lease_release_rejects_duplicate_expiry_descriptors() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x63; 16])?,
        CatalogSecret::from_owned(Box::new([0x64; 32]), Box::new([0x65; 32])),
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
        SegmentProtectionKey::from_owned(Box::new([0x66; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        100,
        std::num::NonZeroU64::new(100).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let identity = lease.identity();
    drop(lease);

    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut duplicate = basis
        .plaintext_objects()
        .find(|bytes| bytes.starts_with(b"PMTC"))
        .ok_or("coupled expiry descriptor")?
        .to_vec();
    duplicate[66..74].copy_from_slice(&101_u64.to_be_bytes());
    objects.push(CatalogObject::new(duplicate)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x67; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    assert_eq!(
        ledger
            .release_snapshot_lease_with_expiry_task(&coordinator, identity)
            .expect_err("duplicate descriptors are ambiguous")
            .code(),
        LedgerFailureCode::StaleGeneration
    );
    assert_eq!(
        super::super::super::snapshot_lease::records(&catalog.pin()?)?.len(),
        1
    );
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        2
    );
    Ok(())
}
