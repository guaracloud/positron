use super::*;
use crate::active_segment_ledger::SegmentRetention;
use crate::{
    MaintenanceCoordinator, MaintenanceTaskPhase, RecoveryWorkClaim, RecoveryWorkKind,
    ResourceAmounts,
};

#[test]
fn retention_publication_retires_an_empty_sealed_segment_and_queues_reclamation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xb1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xb4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(93)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xb5; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
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
    let preparation = active
        .prepare_retention_publication()
        .expect("empty sealed metadata must produce a publication task");
    let publication = preparation.task().clone();
    let publication_id = publication.identity();
    preparation
        .submit_and_persist(&coordinator, &catalog, 12)
        .expect("publication task is durable");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch")
        .expect("empty publication is dispatched");
    let reclamation_id =
        active.complete_running_retention_publication_task(&coordinator, &execution)?;
    assert!(active.snapshot()?.blocks().is_empty());
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("publication")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("reclamation")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    drop(execution);
    let reclamation_execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("reclamation dispatch admission")
        .expect("reclamation dispatch");
    active.complete_running_retention_reclamation_task(&coordinator, &reclamation_execution)?;
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("terminal reclamation")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        MaintenanceCoordinator::restore_from_catalog(&catalog)
            .expect("reclamation restoration")
            .status(reclamation_id)
            .expect("durable terminal reclamation")
            .phase(),
        MaintenanceTaskPhase::Succeeded,
        "physical reclamation and its terminal task record publish atomically"
    );
    Ok(())
}

#[test]
fn retention_publication_uses_canonical_multi_segment_bindings() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xc1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xc4)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(94)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xc5; 32]));
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let first_block = first.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xc6; 16])?,
    )?;
    first.append(first_block.finish(b"first retired log".to_vec())?)?;
    first.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_block = active.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xc7; 16])?,
    )?;
    active.append(second_block.finish(b"second retired log".to_vec())?)?;
    active.seal()?;
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
    let publication = preparation.task().clone();
    assert_eq!(publication.inputs().len(), 2);
    assert_eq!(publication.outputs().len(), 2);
    let publication_id = publication.identity();
    preparation
        .submit_and_persist(&coordinator, &catalog, 12)
        .expect("publication task is durable");
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch")
        .expect("publication is dispatched");
    let reclamation_id =
        active.complete_running_retention_publication_task(&coordinator, &execution)?;
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("publication")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        coordinator
            .status(reclamation_id)
            .expect("reclamation")
            .task()
            .inputs(),
        publication.outputs()
    );
    Ok(())
}

#[test]
fn retention_publication_batches_more_than_sixteen_eligible_segments() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xcf; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xd0; 32]), Box::new([0xd1; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xd2)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(98)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xd3; 32]));
    for raw in 1..=17_u8 {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        let block = ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new([raw; 16])?,
        )?;
        ledger.append(block.finish(vec![raw])?)?;
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
    let preparation = active.prepare_retention_publication()?;
    assert_eq!(preparation.task().inputs().len(), 16);
    assert_eq!(preparation.task().outputs().len(), 16);
    Ok(())
}

#[test]
fn full_catalog_refuses_retention_completion_without_mutating_the_running_task()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(99)?);
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
    sealed.append(block.finish(b"catalog preflight".to_vec())?)?;
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
    let publication_id = preparation.task().identity();
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication start")
        .ok_or("publication dispatch")?;
    let snapshot = catalog.pin()?;
    let mut objects = snapshot
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    for index in objects.len()..1_024 {
        objects.push(CatalogObject::new(
            format!("retention-preflight-{index}").into_bytes(),
        )?);
    }
    catalog.commit(
        snapshot.identity(),
        crate::CatalogProposal::new(
            crate::TransactionId::new([0xe7; 16])?,
            crate::FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let before = catalog.pin()?.number();
    let failure = active
        .complete_running_retention_publication_task(&coordinator, &execution)
        .expect_err("the final proposal must refuse before cloning a full catalog");
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    assert_eq!(catalog.pin()?.number(), before);
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("publication status")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    Ok(())
}

#[test]
fn sequential_publications_preserve_prior_queued_reclamation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xd8; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xd9; 32]), Box::new([0xda; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xdb)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(96)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xdc; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let first_block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xdd; 16])?,
    )?;
    sealed.append(first_block.finish(b"first sequential publication".to_vec())?)?;
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
    let first_preparation = active.prepare_retention_publication()?;
    let first_publication = first_preparation.task().clone();
    let first_publication_id = first_publication.identity();
    first_preparation
        .submit_and_persist(&coordinator, &catalog, 12)
        .expect("first publication is durable");
    let first_execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            12,
            false,
            Some(crate::MaintenanceTaskClass::RetentionPublication),
        )
        .expect("first publication dispatch")
        .ok_or("first publication dispatch")?;
    let first_reclamation =
        active.complete_running_retention_publication_task(&coordinator, &first_execution)?;
    drop(first_execution);
    assert_eq!(
        coordinator
            .status(first_reclamation)
            .expect("first reclamation")
            .phase(),
        MaintenanceTaskPhase::Queued,
        "the first reclamation remains queued while the next publication is prepared"
    );

    let second_block = active.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xde; 16])?,
    )?;
    active.append(second_block.finish(b"second sequential publication".to_vec())?)?;
    active.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_preparation = active.prepare_retention_publication()?;
    let second_publication = second_preparation.task().clone();
    let second_publication_id = second_publication.identity();
    second_preparation
        .submit_and_persist(&coordinator, &catalog, 13)
        .expect("second publication is durable");
    let second_execution = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &authority,
            13,
            false,
            Some(crate::MaintenanceTaskClass::RetentionPublication),
        )
        .expect("second publication dispatch")
        .ok_or("second publication dispatch")?;
    let second_reclamation =
        active.complete_running_retention_publication_task(&coordinator, &second_execution)?;

    assert_eq!(
        coordinator
            .status(first_publication_id)
            .expect("first publication")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        coordinator
            .status(first_reclamation)
            .expect("first reclamation")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    assert_eq!(
        coordinator
            .status(second_publication_id)
            .expect("second publication")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        coordinator
            .status(second_reclamation)
            .expect("second reclamation")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    Ok(())
}

#[test]
fn unavailable_retention_refuses_publication_without_a_successor_or_frontier()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(95)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xd5; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let prepared = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xd6; 16])?,
    )?;
    ledger.append(prepared.finish(b"unavailable retention log".to_vec())?)?;
    ledger.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    active
        .state
        .lock()
        .expect("ledger state")
        .blocks
        .first_mut()
        .expect("retention block")
        .block_retention = SegmentRetention::Unavailable;
    let before = catalog.pin()?.number();
    let failure = active
        .prepare_retention_publication()
        .expect_err("unavailable retention must fail before task publication");
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    assert_eq!(catalog.pin()?.number(), before);
    assert_eq!(
        catalog
            .pin()?
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        0
    );
    Ok(())
}

#[test]
fn retention_publication_refuses_before_planning_when_its_recovery_admission_is_occupied()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(97)?);
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
    sealed.append(block.finish(b"publication admission must precede planning".to_vec())?)?;
    sealed.seal()?;
    elapsed.advance(2_000_000_000)?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    active
        .state
        .lock()
        .expect("ledger state")
        .blocks
        .first_mut()
        .expect("retention block")
        .block_retention = SegmentRetention::Unavailable;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::new([20_000_000, 1, 1, 0, 1_500, 0, 1, 0, 1, 0, 0]),
    )?)?;
    let before = catalog.pin()?.number();
    let failure = active
        .prepare_retention_publication()
        .expect_err("occupied retention capacity must refuse before descriptor planning");
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    assert_eq!(catalog.pin()?.number(), before);
    drop(blocker);
    assert!(
        matches!(
            active.prepare_retention_publication(),
            Err(failure) if failure.code() == LedgerFailureCode::UnsupportedFormat
        ),
        "the admission refusal occurs before malformed metadata is decoded"
    );
    Ok(())
}
