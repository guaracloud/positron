use super::*;

#[test]
fn retention_rejects_a_malformed_signal_block_without_retiring_its_segment()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1f; 16])?,
        CatalogSecret::from_owned(Box::new([0x2f; 32]), Box::new([0x3f; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(15)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5f; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x6f; 16])?,
        vec![0xff],
    )?)?;
    ledger.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5f; 32])),
    )?;

    let failure = LogStore::new()
        .enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?)
        .expect_err("malformed signal bytes cannot become retention evidence");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::MalformedBlock
    );
    assert_eq!(active.snapshot()?.blocks().len(), 1);
    Ok(())
}

#[test]
fn reconstructed_caller_time_cannot_retire_fresh_authenticated_data() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1c; 16])?,
        CatalogSecret::from_owned(Box::new([0x2c; 32]), Box::new([0x3c; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(12)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the fresh retention fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )
    .map_err(|failure| format!("open fresh retention ledger: {failure:?}"))?;
    ledger
        .append(
            store
                .prepare(
                    ledger.begin_store_block(
                        preparation_capacity(&authority, tenant)
                            .map_err(|failure| format!("reserve fresh preparation: {failure:?}"))?,
                        StoreBlockIdentity::new([0x6c; 16])?,
                    )?,
                    vec![record],
                )
                .map_err(|failure| format!("prepare fresh retention block: {failure:?}"))?
                .into_store_block(),
        )
        .map_err(|failure| format!("append fresh retention block: {failure:?}"))?;
    ledger
        .seal()
        .map_err(|failure| format!("seal fresh retention segment: {failure:?}"))?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )
    .map_err(|failure| format!("reopen fresh retention ledger: {failure:?}"))?;
    let snapshot = active
        .snapshot()
        .map_err(|failure| format!("snapshot fresh retention ledger: {failure:?}"))?;
    let block = snapshot
        .blocks()
        .first()
        .ok_or("fresh retention fixture is missing its committed block")?;
    assert_eq!(
        block
            .authenticate_ingest_time(UnixNanoseconds::new(1_000_000_000))
            .expect_err("encoded time must match private v3 block evidence")
            .code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption,
    );
    let duration = NonZeroU64::new(1).ok_or("positive retention duration")?;
    let legacy_payload = block.payload().to_vec();
    drop(snapshot);
    let outcome = active
        .begin_retention(duration)?
        .commit()
        .map_err(|failure| format!("retire fresh retention ledger: {failure:?}"))?;
    assert_eq!(outcome.logically_retired_segments(), 0);
    assert_eq!(active.snapshot()?.blocks().len(), 1);
    let other_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(112)?);
    let other = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        other_scope,
        SegmentProtectionKey::from_owned(Box::new([0x7c; 32])),
    )?;
    other.append(PreparedStoreBlock::new(
        other_scope,
        StoreBlockIdentity::new([0x7c; 16])?,
        legacy_payload,
    )?)?;
    let legacy_snapshot = other.snapshot()?;
    let legacy_block = legacy_snapshot
        .blocks()
        .first()
        .ok_or("legacy fixture block")?;
    let caller_time = legacy_block
        .reconstruct_unretained_ingest_time_for_test(UnixNanoseconds::new(1_000_000_000))?;
    assert_eq!(
        LogRetentionPolicy::new(1)?
            .bucket(tenant, caller_time)
            .expect_err("unretained test time cannot select a retention bucket")
            .code(),
        positron_signals::LogStoreFailureCode::UnsupportedFormat,
    );
    drop(legacy_snapshot);
    other.seal()?;
    let legacy = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        other_scope,
        SegmentProtectionKey::from_owned(Box::new([0x7c; 32])),
    )?;
    let refusal = store
        .enforce_retention(&legacy, tenant, LogRetentionPolicy::new(1)?)
        .expect_err("unauthenticated ingest-time metadata cannot drive public retention");
    assert_eq!(
        refusal.code(),
        positron_signals::LogStoreFailureCode::UnsupportedFormat
    );
    assert_eq!(legacy.snapshot()?.blocks().len(), 1);
    Ok(())
}

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
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
    )?;
    assert_eq!(active.snapshot()?.blocks().len(), 1);

    let rejected =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?)
        })
        .expect_err("a pre-publication catalog sync failure must remain typed");
    assert_eq!(
        rejected.code(),
        positron_signals::LogStoreFailureCode::StaleGeneration
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
        || store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?),
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
        || store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?),
    )
    .expect_err("a later generation without the intended frontier must fence retention");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::StaleGeneration
    );
    assert!(
        active.snapshot()?.blocks().is_empty(),
        "new snapshots cannot expose a segment the latest Catalog keeps Retired"
    );
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
        || store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?),
    )
    .expect_err("stale scoped metadata cannot acknowledge reclaim cleanup");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::StaleGeneration
    );
    assert!(active.snapshot()?.blocks().is_empty());
    drop(active);

    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert!(restarted.snapshot()?.blocks().is_empty());
    store.enforce_retention(&restarted, tenant, LogRetentionPolicy::new(1)?)?;
    Ok(())
}

#[test]
fn partial_physical_reclamation_requires_recovery_and_retries_idempotently()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(18)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the partial reclaim fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0x74; 32]));
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let first_id = first.active_segment_id()?;
    first.append(
        store
            .prepare(
                first.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x75; 16])?,
                )?,
                vec![record.clone()],
            )?
            .into_store_block(),
    )?;
    first.seal()?;
    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let second_id = second.active_segment_id()?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x76; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    second.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let protected = active.snapshot()?;
    assert_eq!(protected.blocks().len(), 2);
    let retired = active
        .begin_retention(NonZeroU64::new(1).ok_or("duration")?)?
        .commit()?;
    assert_eq!(retired.logically_retired_segments(), 2);
    assert_eq!(retired.physically_reclaimed_segments(), 0);
    assert!(active.snapshot()?.blocks().is_empty());
    drop(protected);

    let sealed = root.path().join("segments/sealed");
    let segment_path = |id: positron_kernel::SegmentId| {
        let name = id
            .to_bytes()
            .iter()
            .fold(String::with_capacity(32), |mut name, byte| {
                use std::fmt::Write as _;
                write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
                name
            });
        sealed.join(format!("{name}.segment"))
    };
    let first_path = segment_path(first_id);
    let second_path = segment_path(second_id);
    let second_bytes = std::fs::read(&second_path)?;
    std::fs::remove_file(&second_path)?;
    std::fs::create_dir(&second_path)?;
    let baseline = authority.governor().inspect()?;
    let failure = active
        .begin_retention(NonZeroU64::new(1).ok_or("duration")?)?
        .commit()
        .expect_err("partial physical reclamation cannot be reported as a clean refusal");
    assert_ne!(
        failure.completion_state(),
        LedgerCompletionState::RejectedBeforeMutation
    );
    assert!(active.snapshot()?.blocks().is_empty());
    assert!(!first_path.exists());
    assert!(second_path.is_dir());
    assert_same_resource_usage(&baseline, &authority.governor().inspect()?);

    std::fs::remove_dir(&second_path)?;
    std::fs::write(&second_path, second_bytes)?;
    drop(active);
    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert!(restarted.snapshot()?.blocks().is_empty());
    restarted
        .begin_retention(NonZeroU64::new(1).ok_or("duration")?)?
        .commit()?;
    assert!(!second_path.exists());
    assert_same_resource_usage(&baseline, &authority.governor().inspect()?);
    Ok(())
}

#[test]
fn retired_lease_resume_reserves_capacity_before_recovery_reads() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1e; 16])?,
        CatalogSecret::from_owned(Box::new([0x2e; 32]), Box::new([0x3e; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(14)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the resume accounting fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x6e; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    let lifecycle = retention_clock();
    let now = u64::try_from(
        lifecycle
            .assign_ingest_time()?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .ok_or("lifecycle seconds")?,
    )?;
    let lease = ledger.create_snapshot_lease(now, now + 100)?;
    let lease_identity = lease.identity();
    drop(lease);
    let PolicyEvaluation::Accepted(large) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            None,
            None,
            Some(CandidateAttributeValue::string("x".repeat(200_000))),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the large resume fixture".into());
    };
    let large_record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *large)?;
    for identity in [[0x7e; 16], [0x8e; 16], [0x9e; 16], [0xae; 16]] {
        ledger.append(
            store
                .prepare(
                    ledger.begin_store_block(
                        preparation_capacity(&authority, tenant)?,
                        StoreBlockIdentity::new(identity)?,
                    )?,
                    vec![large_record.clone()],
                )?
                .into_store_block(),
        )?;
    }
    ledger.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
    )?;
    let outcome = store.enforce_retention(&active, tenant, LogRetentionPolicy::new(1)?)?;
    assert_eq!(outcome.expired_segments(), 1);
    assert_eq!(outcome.reclaimed_segments(), 0);
    let segment_path = std::fs::read_dir(root.path().join("segments/sealed"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "segment")
        })
        .ok_or("retired segment payload is missing")?;
    let mut segment = std::fs::read(&segment_path)?;
    let last = segment
        .last_mut()
        .ok_or("retired segment payload is unexpectedly empty")?;
    *last ^= 0xff;
    std::fs::write(&segment_path, segment)?;

    let before = authority.governor().inspect()?;
    let blocker = query_capacity_blocker_leaving(&authority, tenant, 1_100_000)?;
    let blocked = authority.governor().inspect()?;
    let resume_now = active.snapshot_lease_time()?.max(now + 1);
    let refusal = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("capacity refusal must precede retired segment recovery");
    assert_eq!(
        refusal.code(),
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_same_resource_usage(&blocked, &authority.governor().inspect()?);
    drop(blocker);
    let corrupted = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("corrupted retired payload must remain typed after capacity returns");
    assert_eq!(
        corrupted.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    assert_same_resource_usage(&before, &authority.governor().inspect()?);
    std::fs::remove_file(&segment_path)?;
    std::fs::create_dir(&segment_path)?;
    let substituted = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("a retired segment directory substitution must fail before decode");
    assert_eq!(
        substituted.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    assert_same_resource_usage(&before, &authority.governor().inspect()?);
    Ok(())
}
