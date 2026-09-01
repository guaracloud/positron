use super::*;

#[cfg(feature = "test-support")]
#[test]
fn retention_frontier_publication_reconciles_only_durable_ambiguity() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xd1; 16])?,
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(12)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(200));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd4; 32])),
    )?;

    let preparation = preparation_capacity(&authority, tenant)?;
    let resources = authority.governor().inspect()?;
    let blocker_amount = resources
        .recovery_shared_capacity(ResourceDimension::MemoryBytes)
        .checked_sub(resources.usage(ResourceDimension::MemoryBytes))
        .and_then(|available| available.checked_sub(1))
        .ok_or("recovery capacity arithmetic overflow")?;
    let blocker = authority.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, blocker_amount)?,
    )?)?;
    let generation_before_refusal = catalog.pin()?.number();
    let capacity_failure =
        match ledger.begin_store_block(preparation, StoreBlockIdentity::new([0xd5; 16])?) {
            Ok(_) => return Err("frontier publication proceeded without capacity".into()),
            Err(failure) => failure,
        };
    assert_eq!(
        capacity_failure.code(),
        LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(catalog.pin()?.number(), generation_before_refusal);
    drop(blocker);
    assert_eq!(
        authority.governor().inspect()?.recovery_pool_usage(
            RecoveryWorkKind::DurabilityCompletion,
            ResourceDimension::MemoryBytes,
        ),
        0
    );

    let rejected = match with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeCommit,
        0,
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("capacity"),
                StoreBlockIdentity::new([0xd7; 16]).expect("identity"),
            )
        },
    ) {
        Ok(_) => return Err("pre-publication failure was accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(rejected.code(), LedgerFailureCode::StorageUnavailable);

    let reconciled = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("capacity"),
                StoreBlockIdentity::new([0xd6; 16]).expect("identity"),
            )
        },
    )?;
    assert_eq!(reconciled.scope(), scope);
    assert_eq!(reconciled.identity(), StoreBlockIdentity::new([0xd6; 16])?);
    assert_eq!(
        reconciled.ingest_time().instant(),
        UnixNanoseconds::new(200)
    );
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn uncertain_initial_frontier_fences_live_retries_until_reopen_recovers_the_marker()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0xda; 16])?;
    let secret = || CatalogSecret::from_owned(Box::new([0xdb; 32]), Box::new([0xdc; 32]));
    let catalog = Catalog::open(&authority, instance, secret())?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(30)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(400));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xdd; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let baseline = authority.governor().inspect()?;

    let failure = match with_ledger_fault(
        LedgerFileEvent::BeforeRetentionFrontierReconciliation,
        || {
            with_catalog_publication_fault_after(
                CatalogPublicationFault::SynchronizeGenerationDirectory,
                0,
                || {
                    ledger.begin_store_block(
                        preparation_capacity(&authority, tenant).expect("preparation capacity"),
                        StoreBlockIdentity::new([0xde; 16]).expect("block identity"),
                    )
                },
            )
        },
    ) {
        Ok(_) => return Err("unreconciled durable frontier was accepted".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    let retry = match ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xdf; 16])?,
    ) {
        Ok(_) => return Err("frontier-uncertain live ledger accepted a retry".into()),
        Err(failure) => failure,
    };
    assert_eq!(retry.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(authority.governor().inspect()?, baseline);
    drop(ledger);
    drop(catalog);

    let recovered_catalog = Catalog::open(&authority, instance, secret())?;
    let recovered = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &recovered_catalog,
        scope,
        key(),
    )?;
    let recovered_generation = recovered_catalog.pin()?.number();
    let preparation = recovered.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe0; 16])?,
    )?;
    assert_eq!(
        preparation.ingest_time().instant(),
        UnixNanoseconds::new(400)
    );
    assert_eq!(recovered_catalog.pin()?.number(), recovered_generation);
    drop(preparation);
    assert_eq!(authority.governor().inspect()?, baseline);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn divergent_successor_after_ambiguous_initial_frontier_fences_the_live_ledger()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(43)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(500));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    let baseline = authority.governor().inspect()?;

    let failure = match with_catalog_generation_ambiguity_hook_after(
        0,
        |catalog| {
            catalog
                .refresh_after_ambiguous_publication_for_test()
                .expect("recover durable initial frontier");
            let basis = catalog.pin().expect("pin durable initial frontier");
            let objects = basis
                .plaintext_objects()
                .filter(|bytes| !bytes.starts_with(b"PRETFR01"))
                .map(|bytes| CatalogObject::new(bytes.to_vec()).expect("copy bounded object"))
                .collect::<Vec<_>>();
            catalog
                .commit(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([0xe5; 16]).expect("successor transaction"),
                        FormatEpoch::CATALOG_V1,
                        objects,
                    )
                    .expect("successor proposal"),
                    None,
                )
                .expect("publish divergent successor");
        },
        || {
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant).expect("preparation capacity"),
                StoreBlockIdentity::new([0xe6; 16]).expect("block identity"),
            )
        },
    ) {
        Ok(_) => return Err("divergent successor accepted the initial frontier".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::CommitAmbiguous
    );
    let fenced = match ledger.snapshot() {
        Ok(_) => return Err("post-marker divergence left snapshots available".into()),
        Err(failure) => failure,
    };
    assert_eq!(fenced.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(authority.governor().inspect()?, baseline);
    Ok(())
}
