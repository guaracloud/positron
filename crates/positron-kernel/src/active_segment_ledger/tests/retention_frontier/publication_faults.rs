use super::*;
use crate::catalog::{CatalogPublicationFault, with_catalog_publication_fault_sequence_after};
use crate::{MaintenanceCoordinator, MaintenanceObjectId, MaintenanceTaskPhase};

#[test]
fn delayed_retention_publication_proof_retries_the_exact_durable_terminal_pair()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(100)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xf5; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xf6; 16])?,
    )?;
    sealed.append(block.finish(b"ambiguous retention publication".to_vec())?)?;
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
    let publication = preparation.task().clone();
    let publication_id = publication.identity();
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch")
        .expect("publication execution");
    let first = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeGenerationDirectory, 0),
            (CatalogPublicationFault::ReadGenerationDirectory, 0),
        ],
        || active.complete_running_retention_publication_task(&coordinator, &execution),
    )
    .expect_err("durable publication with failed immediate proof is ambiguous");
    assert_eq!(first.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("running task")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    catalog.refresh_state()?;
    assert_eq!(
        coordinator
            .cancel_and_persist(&catalog, publication_id)
            .expect_err("a durable Publication/Reclamation pair cannot be overwritten"),
        crate::MaintenanceFailure::PreconditionFailed
    );
    elapsed.advance(1_000_000_000)?;
    let reclamation_id = active
        .complete_running_retention_publication_task(&coordinator, &execution)
        .expect("same execution must reconcile the exact durable terminal pair");
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
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).expect("restore");
    assert_eq!(
        restored
            .status(publication_id)
            .expect("restored publication")
            .phase(),
        MaintenanceTaskPhase::Succeeded
    );
    assert_eq!(
        restored
            .status(reclamation_id)
            .expect("restored reclamation")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    assert_eq!(
        retention_time.status().safe_anchor(),
        UnixNanoseconds::new(12_000_000_000),
        "the retry must reconcile the live lifecycle authority after exact durable proof"
    );
    Ok(())
}

#[test]
fn retention_publication_uses_its_durable_frontier_after_the_live_clock_advances()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xfa; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xfb; 32]), Box::new([0xfc; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xfd)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(102)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xfe; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xff; 16])?,
    )?;
    sealed.append(block.finish(b"durable frontier".to_vec())?)?;
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
    assert_eq!(
        crate::maintenance::retention_publication_frontier(
            coordinator
                .status(publication_id)
                .expect("durable publication task")
                .checkpoint(),
        )
        .expect("typed durable frontier"),
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(12_000_000_000))
    );
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch")
        .expect("publication execution");
    elapsed.advance(1_000_000_000)?;
    active.complete_running_retention_publication_task(&coordinator, &execution)?;

    assert_eq!(
        crate::active_segment_ledger::retention_frontier::recover(&catalog.pin()?, scope)?,
        Some(crate::IngestTime::from_authenticated_durable(
            UnixNanoseconds::new(12_000_000_000)
        )),
        "the published frontier remains the immutable durable task bound"
    );
    assert_eq!(
        retention_time.status().safe_anchor(),
        UnixNanoseconds::new(13_000_000_000),
        "the live lifecycle authority can advance beyond the durable publication bound"
    );
    Ok(())
}

#[test]
fn cancelled_running_retention_publication_terminalizes_without_retiring_or_queuing()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xd6; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xd7; 32]), Box::new([0xd8; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0xd9)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(103)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xda; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let block = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xdb; 16])?,
    )?;
    sealed.append(block.finish(b"cancelled publication".to_vec())?)?;
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
        .expect("publication dispatch")
        .expect("publication execution");
    coordinator
        .cancel_and_persist(&catalog, publication_id)
        .expect("durable cancellation request");

    let cancellation = active
        .complete_running_retention_publication_task(&coordinator, &execution)
        .expect_err("a cancellation ends this uncommitted publication without a successor");
    assert_eq!(cancellation.code(), LedgerFailureCode::Cancelled);
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("cancelled publication")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert_eq!(
        active.snapshot()?.blocks().len(),
        1,
        "cancellation keeps the sealed segment visible and does not retire it"
    );
    drop(execution);
    assert_eq!(
        authority.governor().inspect()?.recovery_pool_usage(
            crate::RecoveryWorkKind::Retention,
            crate::ResourceDimension::MemoryBytes,
        ),
        0,
        "the cancelled execution releases its dispatch grant"
    );
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog)
        .expect("cancelled Publication restores");
    assert_eq!(
        restored
            .status(publication_id)
            .expect("restored publication")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    assert_eq!(
        restored
            .durable_records()
            .expect("durable task records")
            .len(),
        1,
        "the cancelled Publication does not publish a Reclamation successor"
    );
    Ok(())
}

#[test]
fn delayed_retention_publication_proof_refuses_stale_frontier_and_anchor()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(101)?);
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
    sealed.append(block.finish(b"stale durable proof must not reconcile".to_vec())?)?;
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
    let publication = preparation.task().clone();
    let basis = catalog.pin()?;
    let sealed_metadata = metadata_object_with_binding(&basis, publication.inputs()[0])?;
    assert_eq!(
        MaintenanceObjectId::new(
            CatalogObject::new(sealed_metadata.clone())?
                .identity()
                .to_bytes()
        )
        .expect("catalog object digest is a valid maintenance binding"),
        publication.inputs()[0],
        "the cached metadata is the exact Publication input binding"
    );
    preparation.submit_and_persist(&coordinator, &catalog, 12)?;
    let execution = coordinator
        .start_next_with_reservation_and_persist(&catalog, &authority, 12, false)
        .expect("publication dispatch")
        .expect("publication execution");
    let first = with_catalog_publication_fault_sequence_after(
        &[
            (CatalogPublicationFault::SynchronizeGenerationDirectory, 0),
            (CatalogPublicationFault::ReadGenerationDirectory, 0),
        ],
        || active.complete_running_retention_publication_task(&coordinator, &execution),
    )
    .expect_err("durable publication with failed immediate proof is ambiguous");
    assert_eq!(first.code(), LedgerFailureCode::StorageUnavailable);

    catalog.refresh_state()?;
    let basis = catalog.pin()?;
    let retired_metadata = metadata_object_with_binding(&basis, publication.outputs()[0])?;
    assert_eq!(
        MaintenanceObjectId::new(
            CatalogObject::new(retired_metadata.clone())?
                .identity()
                .to_bytes()
        )
        .expect("catalog object digest is a valid maintenance binding"),
        publication.outputs()[0],
        "the durable metadata is the exact Publication output binding"
    );
    let mut objects = basis
        .plaintext_objects()
        .filter(|object| !object.starts_with(b"PRETFR01") && !object.starts_with(b"PLIFCLK1"))
        .map(|object| CatalogObject::new(object.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(
        crate::active_segment_ledger::retention_frontier::encode(
            scope,
            crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(11_000_000_000)),
        ),
    )?);
    objects.push(CatalogObject::new(retention_time.catalog_anchor_record(
        crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(13_000_000_000)),
    )?)?);
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
        .complete_running_retention_publication_task(&coordinator, &execution)
        .expect_err("a stale frontier or lifecycle anchor must not reconcile a durable pair");
    assert_eq!(failure.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("running publication")
            .phase(),
        MaintenanceTaskPhase::Running
    );
    assert_eq!(
        retention_time.status().safe_anchor(),
        UnixNanoseconds::new(10_000_000_000),
        "a stale frontier must not install even a later durable lifecycle anchor"
    );

    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .filter(|object| !object.starts_with(b"PRETFR01") && !object.starts_with(b"PSEGMET1"))
        .map(|object| CatalogObject::new(object.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(sealed_metadata)?);
    objects.push(CatalogObject::new(
        crate::active_segment_ledger::retention_frontier::encode(
            scope,
            crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(12_000_000_000)),
        ),
    )?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa8; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let metadata_failure = active
        .complete_running_retention_publication_task(&coordinator, &execution)
        .expect_err("cached input metadata cannot prove the publication output binding");
    assert_eq!(metadata_failure.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(
        coordinator
            .status(publication_id)
            .expect("running publication")
            .phase(),
        MaintenanceTaskPhase::Running
    );

    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .filter(|object| !object.starts_with(b"PRETFR01") && !object.starts_with(b"PSEGMET1"))
        .map(|object| CatalogObject::new(object.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(retired_metadata)?);
    objects.push(CatalogObject::new(
        crate::active_segment_ledger::retention_frontier::encode(
            scope,
            crate::IngestTime::from_authenticated_durable(UnixNanoseconds::new(12_000_000_000)),
        ),
    )?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xa9; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let reclamation_id = active
        .complete_running_retention_publication_task(&coordinator, &execution)
        .expect("a later lifecycle anchor must subsume the durable publication bound");
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
    assert_eq!(
        retention_time.status().safe_anchor(),
        UnixNanoseconds::new(13_000_000_000),
        "a later durable lifecycle anchor must be recovered after exact proof"
    );
    Ok(())
}

fn metadata_object_with_binding(
    basis: &crate::CatalogSnapshot,
    expected: MaintenanceObjectId,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut matching = None;
    for bytes in basis
        .plaintext_objects()
        .filter(|bytes| bytes.starts_with(b"PSEGMET1"))
    {
        let binding =
            MaintenanceObjectId::new(CatalogObject::new(bytes.to_vec())?.identity().to_bytes())
                .expect("catalog object digest is a valid maintenance binding");
        if binding == expected && matching.replace(bytes.to_vec()).is_some() {
            return Err("duplicate metadata binding in fixture".into());
        }
    }
    matching.ok_or_else(|| "metadata object for maintenance binding".into())
}
