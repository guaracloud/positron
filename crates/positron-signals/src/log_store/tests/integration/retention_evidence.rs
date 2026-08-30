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
    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5f; 32])),
        &retention_clock(),
    )?;

    let failure = LogStore::new()
        .enforce_retention(
            &active,
            &retention_clock(),
            tenant,
            LogRetentionPolicy::new(1)?,
        )
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
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )
    .map_err(|failure| format!("open fresh retention ledger: {failure:?}"))?;
    ledger
        .append(
            store
                .prepare(
                    preparation_capacity(&authority, tenant)
                        .map_err(|failure| format!("reserve fresh preparation: {failure:?}"))?,
                    &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
                        i64::MAX / 2,
                    ))),
                    tenant,
                    shard,
                    StoreBlockIdentity::new([0x6c; 16])?,
                    vec![record],
                )
                .map_err(|failure| format!("prepare fresh retention block: {failure:?}"))?
                .into_store_block(),
        )
        .map_err(|failure| format!("append fresh retention block: {failure:?}"))?;
    ledger
        .seal()
        .map_err(|failure| format!("seal fresh retention segment: {failure:?}"))?;
    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
        &retention_clock(),
    )
    .map_err(|failure| format!("reopen fresh retention ledger: {failure:?}"))?;
    let snapshot = active
        .snapshot()
        .map_err(|failure| format!("snapshot fresh retention ledger: {failure:?}"))?;
    let block = snapshot
        .blocks()
        .first()
        .ok_or("fresh retention fixture is missing its committed block")?;
    let duration = NonZeroU64::new(1).ok_or("positive retention duration")?;
    let evidence = snapshot.retention_evidence(block, duration)?;
    let legacy_payload = block.payload().to_vec();
    let caller_time = snapshot.reconstruct_ingest_time(UnixNanoseconds::new(1_000_000_000));
    assert_ne!(
        LogRetentionPolicy::new(1)?
            .bucket(tenant, caller_time)?
            .start(),
        LogRetentionPolicy::new(1)?
            .bucket(
                tenant,
                snapshot.reconstruct_ingest_time(UnixNanoseconds::new(i64::MAX / 2)),
            )?
            .start(),
    );
    drop(snapshot);
    let outcome = active
        .retire_expired_sealed_segments(retention_clock().retention_cutoff(duration)?, &[evidence])
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
    let mismatched = other
        .retire_expired_sealed_segments(retention_clock().retention_cutoff(duration)?, &[evidence])
        .expect_err("snapshot evidence cannot authorize another ledger scope");
    assert_eq!(
        mismatched.code(),
        positron_kernel::LedgerFailureCode::PhysicalScopeMismatch
    );
    other.append(PreparedStoreBlock::new(
        other_scope,
        StoreBlockIdentity::new([0x7c; 16])?,
        legacy_payload,
    )?)?;
    let unavailable_snapshot = other.snapshot()?;
    let unavailable_block = unavailable_snapshot
        .blocks()
        .first()
        .ok_or("legacy retention fixture is missing its block")?;
    let unavailable = unavailable_snapshot
        .retention_evidence(unavailable_block, duration)
        .expect_err("blocks without authenticated ingest-time metadata cannot authorize expiry");
    assert_eq!(
        unavailable.code(),
        positron_kernel::LedgerFailureCode::UnsupportedFormat
    );
    assert_eq!(other.snapshot()?.blocks().len(), 1);
    drop(unavailable_snapshot);
    other.seal()?;
    let legacy = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        other_scope,
        SegmentProtectionKey::from_owned(Box::new([0x7c; 32])),
        &retention_clock(),
    )?;
    let refusal = store
        .enforce_retention(
            &legacy,
            &retention_clock(),
            tenant,
            LogRetentionPolicy::new(1)?,
        )
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
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x6d; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
        &retention_clock(),
    )?;
    assert_eq!(active.snapshot()?.blocks().len(), 1);

    let rejected =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            store.enforce_retention(
                &active,
                &retention_clock(),
                tenant,
                LogRetentionPolicy::new(1)?,
            )
        })
        .expect_err("a pre-publication catalog sync failure must remain typed");
    assert_eq!(
        rejected.code(),
        positron_signals::LogStoreFailureCode::StorageUnavailable
    );
    assert_eq!(active.snapshot()?.blocks().len(), 1);

    let outcome = with_catalog_publication_fault_after(
        CatalogPublicationFault::SynchronizeGenerationDirectory,
        0,
        || {
            store.enforce_retention(
                &active,
                &retention_clock(),
                tenant,
                LogRetentionPolicy::new(1)?,
            )
        },
    )?;
    assert_eq!(outcome.expired_segments(), 1);
    assert!(active.snapshot()?.blocks().is_empty());
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
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                preparation_capacity(&authority, tenant)?,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1))),
                tenant,
                shard,
                StoreBlockIdentity::new([0x6e; 16])?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    ledger.seal()?;
    let lifecycle = retention_clock();
    let now = u64::try_from(
        lifecycle
            .assign_ingest_time()?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .ok_or("lifecycle seconds")?,
    )?;
    let active = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
        &lifecycle,
    )?;
    let lease = active.create_snapshot_lease(now, now + 100)?;
    let lease_identity = lease.identity();
    drop(lease);
    let outcome =
        store.enforce_retention(&active, &lifecycle, tenant, LogRetentionPolicy::new(1)?)?;
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
    let blocker = query_capacity_blocker(&authority, tenant)?;
    let blocked = authority.governor().inspect()?;
    let refusal = active
        .resume_snapshot_lease(lease_identity, now + 1)
        .expect_err("capacity refusal must precede retired segment recovery");
    assert_eq!(
        refusal.code(),
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_same_resource_usage(&blocked, &authority.governor().inspect()?);
    drop(blocker);
    let corrupted = active
        .resume_snapshot_lease(lease_identity, now + 1)
        .expect_err("corrupted retired payload must remain typed after capacity returns");
    assert_eq!(
        corrupted.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    assert_same_resource_usage(&before, &authority.governor().inspect()?);
    Ok(())
}
