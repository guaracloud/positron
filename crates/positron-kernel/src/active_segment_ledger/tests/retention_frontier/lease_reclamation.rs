use super::*;

#[test]
fn sealed_nonempty_segment_expires_only_after_authoritative_elapsed_time()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0x21; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x23; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0x2f)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(17)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x24; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let prepared = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x25; 16])?,
    )?;
    sealed.append(prepared.finish(b"retained".to_vec())?)?;
    sealed.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let fresh = active.begin_retention()?;
    assert_eq!(fresh.blocks().len(), 1);
    let fresh_outcome = fresh.commit()?;
    assert_eq!(fresh_outcome.logically_retired_segments(), 0);
    assert_eq!(fresh_outcome.physically_reclaimed_segments(), 0);

    elapsed.advance(2_000_000_000)?;
    let expired = active.begin_retention()?;
    assert_eq!(
        expired.blocks().first().map(|block| block.payload()),
        Some(b"retained".as_slice()),
        "the expired evaluation must expose its pinned inspected block"
    );
    let outcome = expired.commit()?;
    assert_eq!(outcome.logically_retired_segments(), 1);
    assert_eq!(outcome.physically_reclaimed_segments(), 1);
    assert!(active.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn restart_wall_jump_cannot_expire_a_durable_lease_or_reclaim_its_segment()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0x26; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x27; 32]), Box::new([0x28; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0x2e)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(18)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x29; 32]));
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(100_000_000_000),
    );
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let prepared = sealed.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x2a; 16])?,
    )?;
    sealed.append(prepared.finish(b"leased-retention".to_vec())?)?;
    sealed.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        active
            .create_snapshot_lease(150, 250)
            .expect_err("raw lease time cannot enter a retention ledger")
            .code(),
        LedgerFailureCode::InvalidInput
    );
    assert_eq!(
        active
            .create_snapshot_lease_at_catalog(150, 250, catalog.pin()?.identity())
            .expect_err("raw Catalog-bound lease time cannot enter a retention ledger")
            .code(),
        LedgerFailureCode::InvalidInput
    );
    let lease =
        active.create_snapshot_lease_for(150, NonZeroU64::new(100).ok_or("lease duration")?)?;
    assert_eq!(lease.expiry(), 200);
    assert_eq!(
        active.snapshot_lease_time()?,
        100,
        "caller wall time must not become the durable Log lease observation"
    );
    let mut lease_identity = lease.identity();
    drop(lease);
    assert_eq!(
        active
            .prepare_snapshot_lease_replacement(lease_identity, 150, 250)
            .err()
            .ok_or("raw lease replacement unexpectedly entered a retention ledger")?
            .code(),
        LedgerFailureCode::InvalidInput
    );
    elapsed.advance(2_000_000_000)?;
    let mut replacement = active.prepare_snapshot_lease_replacement_for(
        lease_identity,
        u64::MAX - 100,
        NonZeroU64::new(100).ok_or("replacement duration")?,
    )?;
    let replacement = replacement.commit()?;
    assert_eq!(
        active.snapshot_lease_time()?,
        102,
        "replacement observation must ignore the fallback QueryClock"
    );
    assert_eq!(replacement.expiry(), 202);
    lease_identity = replacement.identity();
    drop(replacement);
    drop(active);

    let (conservative_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX / 3));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &conservative_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        active.snapshot_lease_time()?,
        102,
        "a lease observation above the durable retention frontier becomes a conservative floor"
    );
    assert_eq!(
        active.snapshot_lease_usage(lease_identity, 0)?,
        SnapshotLeaseUsage::default(),
        "a caller observation below the durable floor must not make the lease unreadable"
    );
    assert_eq!(
        active.snapshot_lease_time()?,
        102,
        "reading lease usage must not regress the conservative observation floor"
    );
    let retired = active.begin_retention()?.commit()?;
    assert_eq!(
        retired.evaluated_at(),
        UnixNanoseconds::new(100_000_000_000),
        "restart must rebase destructive time from authenticated data, not the lease floor"
    );
    assert_eq!(retired.logically_retired_segments(), 1);
    assert_eq!(
        retired.physically_reclaimed_segments(),
        1,
        "only the empty predecessor created by restart is reclaimable"
    );
    drop(active);

    let (restarted_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX / 2));
    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &restarted_time,
        &catalog,
        scope,
        key(),
    )?;
    let resumed = restarted.resume_snapshot_lease(lease_identity, 150)?;
    assert_eq!(resumed.snapshot().blocks().len(), 1);
    assert_eq!(
        resumed.snapshot().blocks()[0].payload(),
        b"leased-retention"
    );
    drop(resumed);
    Ok(())
}

#[test]
fn retention_domain_lease_derives_observation_and_expiry_from_one_sample()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0x31; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0x39)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(27)?);
    let retention_time = RetentionTimeAuthority::establish_with_stepping_elapsed(
        UnixNanoseconds::new(100_000_000_000),
        1_000_000_000,
    );
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
    )?;

    let lease = ledger
        .create_snapshot_lease_for(u64::MAX, NonZeroU64::new(1).ok_or("one-second lease")?)?;
    assert_eq!(lease.expiry(), 101);
    Ok(())
}

#[test]
fn retention_domain_lease_replacement_uses_one_authority_sample() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x35; 16])?,
        CatalogSecret::from_owned(Box::new([0x36; 32]), Box::new([0x37; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(28)?);
    let retention_time = RetentionTimeAuthority::establish_with_stepping_elapsed(
        UnixNanoseconds::new(100_000_000_000),
        1_000_000_000,
    );
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x38; 32])),
    )?;
    let lease = ledger
        .create_snapshot_lease_for(u64::MAX, NonZeroU64::new(10).ok_or("ten-second lease")?)?;
    let identity = lease.identity();
    drop(lease);

    let mut replacement = ledger.prepare_snapshot_lease_replacement_for(
        identity,
        u64::MAX,
        NonZeroU64::new(1).ok_or("one-second replacement")?,
    )?;
    let replacement = replacement.commit()?;
    assert_eq!(replacement.expiry(), 102);
    Ok(())
}

#[test]
fn prepared_lease_replacement_cannot_commit_below_the_advanced_durable_floor()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x45; 16])?,
        CatalogSecret::from_owned(Box::new([0x46; 32]), Box::new([0x47; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(29)?);
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(100_000_000_000),
    );
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x48; 32])),
    )?;
    let old =
        ledger.create_snapshot_lease_for(0, NonZeroU64::new(1_000).ok_or("old lease duration")?)?;
    let old_identity = old.identity();
    drop(old);

    elapsed.advance(1_000_000_000)?;
    let mut replacement = ledger.prepare_snapshot_lease_replacement_for(
        old_identity,
        0,
        NonZeroU64::new(99).ok_or("candidate lease duration")?,
    )?;
    let candidate_identity = replacement.identity();
    elapsed.advance(799_000_000_000)?;
    drop(ledger.resume_snapshot_lease(old_identity, 0)?);
    assert_eq!(ledger.snapshot_lease_time()?, 900);
    let before_catalog = catalog.pin()?;
    let before_resources = authority.governor().inspect()?;

    let failure = replacement
        .commit()
        .expect_err("a candidate expired at the durable floor cannot replace an active lease");
    assert_eq!(failure.code(), LedgerFailureCode::SnapshotExpired);
    let after_catalog = catalog.pin()?;
    assert_eq!(after_catalog.identity(), before_catalog.identity());
    assert_eq!(after_catalog.number(), before_catalog.number());
    assert_eq!(authority.governor().inspect()?, before_resources);
    assert_eq!(ledger.snapshot_lease_time()?, 900);
    assert_eq!(
        ledger.resume_snapshot_lease(old_identity, 0)?.identity(),
        old_identity
    );
    assert_eq!(
        ledger
            .snapshot_lease_usage(candidate_identity, 0)
            .expect_err("the rejected candidate must not enter the Catalog")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn prepared_lease_replacement_rejects_an_observation_below_the_advanced_floor()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x49; 16])?,
        CatalogSecret::from_owned(Box::new([0x4a; 32]), Box::new([0x4b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(30)?);
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(100_000_000_000),
    );
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x4c; 32])),
    )?;
    let old =
        ledger.create_snapshot_lease_for(0, NonZeroU64::new(1_000).ok_or("old lease duration")?)?;
    let old_identity = old.identity();
    drop(old);

    elapsed.advance(1_000_000_000)?;
    let mut replacement = ledger.prepare_snapshot_lease_replacement_for(
        old_identity,
        0,
        NonZeroU64::new(1_000).ok_or("candidate lease duration")?,
    )?;
    let candidate_identity = replacement.identity();
    elapsed.advance(799_000_000_000)?;
    drop(ledger.resume_snapshot_lease(old_identity, 0)?);
    let before_catalog = catalog.pin()?;
    let before_resources = authority.governor().inspect()?;

    let failure = replacement
        .commit()
        .expect_err("a candidate observed below the durable floor must be stale");
    assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);
    let after_catalog = catalog.pin()?;
    assert_eq!(after_catalog.identity(), before_catalog.identity());
    assert_eq!(after_catalog.number(), before_catalog.number());
    assert_eq!(authority.governor().inspect()?, before_resources);
    assert_eq!(ledger.snapshot_lease_time()?, 900);
    assert_eq!(
        ledger.resume_snapshot_lease(old_identity, 0)?.identity(),
        old_identity
    );
    assert_eq!(
        ledger
            .snapshot_lease_usage(candidate_identity, 0)
            .expect_err("the stale candidate must not enter the Catalog")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn prepared_lease_replacement_expires_when_another_replacement_wins() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x4d; 16])?,
        CatalogSecret::from_owned(Box::new([0x4e; 32]), Box::new([0x4f; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(31)?);
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(100_000_000_000),
    );
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x50; 32])),
    )?;
    let old =
        ledger.create_snapshot_lease_for(0, NonZeroU64::new(1_000).ok_or("old lease duration")?)?;
    let old_identity = old.identity();
    drop(old);

    elapsed.advance(1_000_000_000)?;
    let mut losing_replacement = ledger.prepare_snapshot_lease_replacement_for(
        old_identity,
        0,
        NonZeroU64::new(1_000).ok_or("losing replacement duration")?,
    )?;
    let losing_identity = losing_replacement.identity();
    let mut winning_replacement = ledger.prepare_snapshot_lease_replacement_for(
        old_identity,
        0,
        NonZeroU64::new(1_000).ok_or("winning replacement duration")?,
    )?;
    let winning_identity = winning_replacement.identity();
    drop(winning_replacement.commit()?);
    let before_catalog = catalog.pin()?;
    let before_resources = authority.governor().inspect()?;

    let failure = losing_replacement
        .commit()
        .expect_err("the replaced durable identity must expire an older preparation");
    assert_eq!(failure.code(), LedgerFailureCode::SnapshotExpired);
    let after_catalog = catalog.pin()?;
    assert_eq!(after_catalog.identity(), before_catalog.identity());
    assert_eq!(after_catalog.number(), before_catalog.number());
    assert_eq!(authority.governor().inspect()?, before_resources);
    assert_eq!(
        ledger
            .resume_snapshot_lease(winning_identity, 0)?
            .identity(),
        winning_identity
    );
    assert_eq!(
        ledger
            .snapshot_lease_usage(losing_identity, 0)
            .expect_err("the losing replacement must not enter the Catalog")
            .code(),
        LedgerFailureCode::SnapshotExpired
    );
    Ok(())
}

#[test]
fn empty_sealed_segment_is_logically_retired_and_physically_reclaimed() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0x31; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0x3a)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(17)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(2_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0x34; 32]));
    ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?
    .seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let outcome = active.begin_retention()?.commit()?;
    assert_eq!(outcome.logically_retired_segments(), 1);
    assert_eq!(outcome.physically_reclaimed_segments(), 1);
    assert_eq!(outcome.evaluated_at(), UnixNanoseconds::new(2_000_000_000));
    assert!(active.snapshot()?.blocks().is_empty());
    drop(active);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert!(reopened.snapshot()?.blocks().is_empty());
    Ok(())
}
