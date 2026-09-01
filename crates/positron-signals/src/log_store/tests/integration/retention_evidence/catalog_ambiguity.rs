use super::*;

#[test]
fn retired_catalog_rename_is_reconciled_before_new_snapshots() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1d; 16])?,
        CatalogSecret::from_owned(Box::new([0x2d; 32]), Box::new([0x3d; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(13)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the catalog ambiguity fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x6d; 16])?,
                )?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
    )?;
    assert_eq!(active.snapshot()?.blocks().len(), 1);
    let policy = retention_policy(&catalog, &active, tenant, 1)?;

    let rejected =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            store.enforce_retention(&active, tenant, policy)
        })
        .expect_err("a pre-publication catalog sync failure must remain typed");
    assert_eq!(
        rejected.code(),
        positron_signals::LogStoreFailureCode::StorageUnavailable
    );
    assert_eq!(active.snapshot()?.blocks().len(), 1);

    let outcome = with_catalog_generation_ambiguity_hook_after(
        0,
        |catalog| {
            catalog
                .refresh_after_ambiguous_publication_for_test()
                .expect("N+1 must be recoverable before publishing N+2");
            let basis = catalog.pin().expect("pin N+1");
            let mut objects = basis
                .object_identities()
                .map(|identity| {
                    CatalogObject::new(
                        basis
                            .object(identity)
                            .expect("read N+1 object")
                            .expect("N+1 object exists")
                            .to_vec(),
                    )
                    .expect("copy N+1 object")
                })
                .collect::<Vec<_>>();
            objects.push(CatalogObject::new(b"retention N+2".to_vec()).expect("N+2 object"));
            catalog
                .commit(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([0x7d; 16]).expect("N+2 transaction"),
                        FormatEpoch::CATALOG_V1,
                        objects,
                    )
                    .expect("N+2 proposal"),
                    None,
                )
                .expect("publish N+2");
        },
        || store.enforce_retention(&active, tenant, policy),
    )?;
    assert_eq!(outcome.expired_segments(), 1);
    assert!(active.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn later_catalog_conflict_hides_segments_already_published_as_retired() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x21; 16])?,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x23; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(16)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the divergent N+2 fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x24; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x25; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x24; 32])),
    )?;

    let policy = retention_policy(&catalog, &active, tenant, 1)?;
    let failure = with_catalog_generation_ambiguity_hook_after(
        0,
        |catalog| {
            catalog
                .refresh_after_ambiguous_publication_for_test()
                .expect("recover divergent N+1");
            let basis = catalog.pin().expect("pin divergent N+1");
            let objects = basis
                .object_identities()
                .filter_map(|identity| {
                    let bytes = basis
                        .object(identity)
                        .expect("read divergent N+1 object")
                        .expect("divergent N+1 object exists");
                    (!bytes.starts_with(b"PRETFR01")).then(|| {
                        CatalogObject::new(bytes.to_vec()).expect("copy divergent N+1 object")
                    })
                })
                .collect::<Vec<_>>();
            catalog
                .commit(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([0x26; 16]).expect("divergent N+2 transaction"),
                        FormatEpoch::CATALOG_V1,
                        objects,
                    )
                    .expect("divergent N+2 proposal"),
                    None,
                )
                .expect("publish divergent N+2");
        },
        || store.enforce_retention(&active, tenant, policy),
    )
    .expect_err("a later generation without the intended frontier must fence retention");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::StaleGeneration
    );
    let fence = match active.snapshot() {
        Ok(_) => return Err("ambiguous publication did not fence the live ledger".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        fence.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x24; 32])),
    )?;
    assert!(reopened.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn reclaim_cleanup_rejects_a_later_catalog_that_keeps_the_removed_scope_superset()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(17)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the reclaim fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0x34; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    sealed.append(
        store
            .prepare(
                sealed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x35; 16])?,
                )?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    sealed.seal()?;
    let second_sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    second_sealed.append(
        store
            .prepare(
                second_sealed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x37; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    second_sealed.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;

    let policy = retention_policy(&catalog, &active, tenant, 1)?;
    let failure = with_catalog_publication_ambiguity_hook_after(
        CatalogPublicationFault::SynchronizeCommit,
        1,
        |catalog| {
            catalog
                .refresh_after_ambiguous_publication_for_test()
                .expect("refresh pre-durable cleanup failure");
            let basis = catalog.pin().expect("pin stale-superset basis");
            let mut objects = basis
                .object_identities()
                .map(|identity| {
                    CatalogObject::new(
                        basis
                            .object(identity)
                            .expect("read basis object")
                            .expect("basis object exists")
                            .to_vec(),
                    )
                    .expect("copy basis object")
                })
                .collect::<Vec<_>>();
            objects.push(CatalogObject::new(b"unrelated N+2 control".to_vec()).expect("control"));
            catalog
                .commit(
                    basis.identity(),
                    CatalogProposal::new(
                        TransactionId::new([0x36; 16]).expect("N+2 transaction"),
                        FormatEpoch::CATALOG_V1,
                        objects,
                    )
                    .expect("N+2 proposal"),
                    None,
                )
                .expect("publish stale-superset N+2");
        },
        || store.enforce_retention(&active, tenant, policy),
    )
    .expect_err("stale scoped metadata cannot acknowledge reclaim cleanup");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::StaleGeneration
    );
    let fence = match active.snapshot() {
        Ok(_) => return Err("ambiguous cleanup did not fence the live ledger".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        fence.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    drop(active);

    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert!(restarted.snapshot()?.blocks().is_empty());
    store.enforce_retention(
        &restarted,
        tenant,
        retention_policy(&catalog, &restarted, tenant, 1)?,
    )?;
    Ok(())
}
