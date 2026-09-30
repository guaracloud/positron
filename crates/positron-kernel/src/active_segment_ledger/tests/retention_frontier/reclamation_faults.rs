use super::*;
use crate::catalog::{CatalogPublicationFault, with_catalog_publication_fault_sequence_after};
use crate::{MaintenanceCoordinator, MaintenanceTaskPhase};
use std::sync::{Arc, Mutex};

struct MutableWallClock(Arc<Mutex<UnixNanoseconds>>);

impl crate::LifecycleClockSource for MutableWallClock {
    fn read(&self) -> Result<UnixNanoseconds, crate::LifecycleClockFailure> {
        self.0
            .lock()
            .map(|instant| *instant)
            .map_err(|_| crate::LifecycleClockFailure::Unavailable)
    }
}

#[test]
fn delayed_reclamation_proof_reconciles_the_exact_terminal_record_after_physical_unlink()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xd1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xd4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(106)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xd5; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xd6; 16])?,
    )?;
    sealed.append(block.finish(b"ambiguous physical reclamation".to_vec())?)?;
    sealed.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let preparation = active.prepare_retention_publication()?;
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let publication_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch admission")
        .ok_or("publication dispatch")?;
    let reclamation_id =
        active.complete_running_retention_publication_task(&coordinator, &publication_execution)?;
    drop(publication_execution);
    let reclamation_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("reclamation dispatch admission")
        .ok_or("reclamation dispatch")?;

    let first = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeGenerationDirectory, 0),
            (CatalogPublicationFault::ReadGenerationDirectory, 0),
        ],
        || active.complete_running_retention_reclamation_task(&coordinator, &reclamation_execution),
    )
    .expect_err("a durable physical completion without immediate proof is ambiguous");
    assert_eq!(first.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("running task")
            .phase(),
        MaintenanceTaskPhase::Running,
        "the unproved completion must retain its durable execution for exact recovery"
    );

    active.complete_running_retention_reclamation_task(&coordinator, &reclamation_execution)?;
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("reconciled task")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("reclamation restoration")
            .status(reclamation_id)
            .expect("restored terminal task")
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "same-process retry and reopen must converge on the exact durable terminal record"
    );
    Ok(())
}

#[test]
fn uncertain_clock_reclamation_protects_existing_leases_but_reclaims_after_release()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xe1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xe4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(107)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xe5; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe6; 16])?,
    )?;
    sealed.append(block.finish(b"uncertain retained log".to_vec())?)?;
    sealed.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let lease = active.create_snapshot_lease_for(12, NonZeroU64::new(100).ok_or("lease ttl")?)?;
    let lease_identity = lease.identity();
    drop(lease);
    let coordinator = MaintenanceCoordinator::new();
    let preparation = active.prepare_retention_publication()?;
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let publication_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch admission")
        .ok_or("publication dispatch")?;
    let reclamation_id =
        active.complete_running_retention_publication_task(&coordinator, &publication_execution)?;
    drop(publication_execution);
    drop(active);

    let wall = Arc::new(Mutex::new(UnixNanoseconds::new(200_000_000_000)));
    let (uncertain_time, _) = RetentionTimeAuthority::establish_with_source_and_manual_elapsed(
        MutableWallClock(Arc::clone(&wall)),
        crate::LifecycleClockPolicy::new(10)?,
    )?;
    let uncertain = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &uncertain_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        uncertain_time.status().state(),
        crate::LifecycleClockState::ClockUncertain
    );
    let protected_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("protected dispatch admission")
        .ok_or("protected dispatch")?;
    uncertain.complete_running_retention_reclamation_task(&coordinator, &protected_execution)?;
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("protected status")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "an uncertain clock must conservatively retain every matching durable lease"
    );
    drop(protected_execution);
    uncertain.release_snapshot_lease(lease_identity)?;
    let eligible_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("eligible dispatch admission")
        .ok_or("eligible dispatch")?;
    uncertain.complete_running_retention_reclamation_task(&coordinator, &eligible_execution)?;
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("terminal status")
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "clock uncertainty must not strand a reclaim task with no durable lease"
    );
    Ok(())
}

#[test]
fn reclamation_restores_the_same_descriptor_after_partial_physical_unlink()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xf1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xf4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(108)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xf5; 32]));
    for (identity, payload) in [
        ([0xf6; 16], b"first partial reclaim".as_slice()),
        ([0xf7; 16], b"second partial reclaim".as_slice()),
    ] {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        let block = ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new(identity)?,
        )?;
        ledger.append(block.finish(payload.to_vec())?)?;
        ledger.seal()?;
    }
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let preparation = active.prepare_retention_publication()?;
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let publication_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch admission")
        .ok_or("publication dispatch")?;
    let reclamation_id =
        active.complete_running_retention_publication_task(&coordinator, &publication_execution)?;
    drop(publication_execution);
    let retired = active
        .storage
        .catalog_segments(&catalog.pin()?, scope)?
        .into_iter()
        .filter(|metadata| metadata.state == crate::active_segment_ledger::SegmentState::Retired)
        .collect::<Vec<_>>();
    assert_eq!(
        retired.len(),
        2,
        "publication must bind both retired inputs"
    );
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("reclamation dispatch admission")
        .ok_or("reclamation dispatch")?;
    let failure =
        with_ledger_faults_after(&[(LedgerFileEvent::BeforeReclaimRetiredSegment, 1)], || {
            active.complete_running_retention_reclamation_task(&coordinator, &execution)
        })
        .expect_err("the second physical unlink must report a post-mutation failure");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.completion_state(),
        crate::LedgerCompletionState::RecoveryRequired
    );
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("running reclamation")
            .phase(),
        MaintenanceTaskPhase::Running,
        "the original durable descriptor must remain running after partial physical mutation"
    );
    assert!(
        !active.storage.reclaim_retired(retired[0])?,
        "the first exact retired input must already be physically absent"
    );
    drop(execution);
    drop(coordinator);
    drop(active);

    let coordinator = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .expect("reopen after physical failure");
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("durable running reclamation")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the unchanged durable record must make post-crash retry schedulable"
    );
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let restored_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("restored reclamation dispatch admission")
        .ok_or("restored reclamation dispatch")?;
    reopened.complete_running_retention_reclamation_task(&coordinator, &restored_execution)?;
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("terminal reclamation")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    let terminal_metadata = reopened
        .storage
        .catalog_segments(&catalog.pin()?, scope)?
        .into_iter()
        .filter(|metadata| metadata.state == crate::active_segment_ledger::SegmentState::Retired)
        .collect::<Vec<_>>();
    assert_eq!(
        terminal_metadata.len(),
        1,
        "the terminal Catalog metadata must retain only the exact continuity marker"
    );
    assert_eq!(terminal_metadata[0].id, retired[1].id);
    assert!(
        !reopened.storage.reclaim_retired(retired[0])?
            && !reopened.storage.reclaim_retired(retired[1])?,
        "the restored execution must leave both exact retired payloads physically absent"
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("terminal recovery")
            .status(reclamation_id)
            .expect("restored terminal reclamation")
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "a missing first file is idempotent while the same durable descriptor reclaims the remainder"
    );
    Ok(())
}

#[test]
fn reclamation_reconciliation_refuses_a_durable_terminal_record_without_its_continuity_marker()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xa1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xa4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(109)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xa5; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xa6; 16])?,
    )?;
    sealed.append(block.finish(b"tampered reclamation continuity".to_vec())?)?;
    sealed.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let preparation = active.prepare_retention_publication()?;
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let publication_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch admission")
        .ok_or("publication dispatch")?;
    let reclamation_id =
        active.complete_running_retention_publication_task(&coordinator, &publication_execution)?;
    drop(publication_execution);
    let reclamation_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("reclamation dispatch admission")
        .ok_or("reclamation dispatch")?;
    let first = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeGenerationDirectory, 0),
            (CatalogPublicationFault::ReadGenerationDirectory, 0),
        ],
        || active.complete_running_retention_reclamation_task(&coordinator, &reclamation_execution),
    )
    .expect_err("the completed physical mutation must await an exact durable proof");
    assert_eq!(first.code(), LedgerFailureCode::StorageUnavailable);
    catalog.refresh_state()?;
    let basis = catalog.pin()?;
    let continuity = active
        .storage
        .catalog_segments(&basis, scope)?
        .into_iter()
        .find(|metadata| metadata.state == crate::active_segment_ledger::SegmentState::Retired)
        .ok_or("published continuity marker")?;
    let continuity_bytes = active.storage.metadata_object(continuity);
    let objects = basis
        .plaintext_objects()
        .filter(|bytes| *bytes != continuity_bytes.as_slice())
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa7; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let failure = active
        .complete_running_retention_reclamation_task(&coordinator, &reclamation_execution)
        .expect_err("a terminal record without the exact continuity publication must not install");
    assert_eq!(failure.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("live task")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    Ok(())
}
