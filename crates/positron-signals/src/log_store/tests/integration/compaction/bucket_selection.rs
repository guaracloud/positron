use super::*;

#[test]
fn compaction_keeps_sealed_segments_in_other_retention_buckets_untouched()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe1; 16])?,
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(1_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xe4; 32]));
    let store = LogStore::new();
    let first = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &first, tenant, 2)?;
    let first_preparation = first.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe5; 16])?,
    )?;
    first.append(
        store
            .prepare(first_preparation, vec![record("old bucket")?])?
            .into_store_block(),
    )?;
    first.seal()?;
    elapsed.advance(3_000_000_000)?;
    let second = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    second.append(
        store
            .prepare(
                second.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xe6; 16])?,
                )?,
                vec![record("new bucket one")?],
            )?
            .into_store_block(),
    )?;
    second.seal()?;

    let third = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    third.append(
        store
            .prepare(
                third.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xe7; 16])?,
                )?,
                vec![record("new bucket two")?],
            )?
            .into_store_block(),
    )?;
    third.seal()?;

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let snapshot = active.snapshot()?;
    let before = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    let old_bucket = policy.bucket(
        tenant,
        before
            .records()
            .first()
            .ok_or("old retention bucket fixture record missing")?
            .ingest_time(),
    )?;
    let target = policy.bucket(
        tenant,
        before
            .records()
            .get(1)
            .ok_or("new retention bucket fixture record missing")?
            .ingest_time(),
    )?;
    assert_ne!(old_bucket, target);
    assert!(before.records().iter().skip(1).all(|record| {
        policy
            .bucket(tenant, record.ingest_time())
            .is_ok_and(|bucket| bucket == target)
    }));
    let outcome = store.compact(&active, tenant, policy, target)?;
    assert_eq!(outcome.input_segments(), 2);
    assert_eq!(outcome.output_segments(), 1);
    let after = store.scan(
        authority.governor(),
        tenant,
        &active.snapshot()?,
        LogScan::all(ScanLimit::new(10)?),
    )?;
    assert_eq!(after.records().len(), 3);
    assert_eq!(
        after.records()[0].record().body(),
        before.records()[0].record().body()
    );
    drop(snapshot);
    drop(before);
    drop(after);
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        store
            .scan(
                authority.governor(),
                tenant,
                &reopened.snapshot()?,
                LogScan::all(ScanLimit::new(10)?),
            )?
            .records()
            .len(),
        3
    );
    Ok(())
}

#[test]
fn compaction_skips_mixed_bucket_segments_and_compacts_complete_targets()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0xa1; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(1_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xa4; 32]));
    let store = LogStore::new();
    let mixed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let policy = retention_policy(&catalog, &mixed, tenant, 2)?;
    mixed.append(
        store
            .prepare(
                mixed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xa5; 16])?,
                )?,
                vec![record("mixed-old-bucket")?],
            )?
            .into_store_block(),
    )?;
    elapsed.advance(3_000_000_000)?;
    mixed.append(
        store
            .prepare(
                mixed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xa6; 16])?,
                )?,
                vec![record("mixed-target-bucket")?],
            )?
            .into_store_block(),
    )?;
    let mixed_segment = mixed.seal()?.segment_id();

    for (identity, body) in [
        ([0xa7; 16], "complete-target-one"),
        ([0xa8; 16], "complete-target-two"),
    ] {
        let segment = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        segment.append(
            store
                .prepare(
                    segment.begin_store_block(
                        preparation_capacity(&authority, tenant)?,
                        StoreBlockIdentity::new(identity)?,
                    )?,
                    vec![record(body)?],
                )?
                .into_store_block(),
        )?;
        segment.seal()?;
    }

    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let before_snapshot = active.snapshot()?;
    let before_scan = store.scan(
        authority.governor(),
        tenant,
        &before_snapshot,
        LogScan::all(ScanLimit::new(16)?),
    )?;
    let target_bucket = policy.bucket(
        tenant,
        before_scan
            .records()
            .get(1)
            .ok_or("mixed-bucket target record is missing")?
            .ingest_time(),
    )?;
    let expected = before_scan
        .records()
        .iter()
        .map(|record| {
            (
                record.record().clone(),
                record.commit_position(),
                record.record_ordinal(),
            )
        })
        .collect::<Vec<_>>();
    drop(before_scan);
    drop(before_snapshot);
    let governor_before = authority.governor().inspect()?;
    let outcome = store.compact(&active, tenant, policy, target_bucket)?;
    assert_eq!(outcome.input_segments(), 2);
    assert_eq!(outcome.output_segments(), 1);
    let governor_after = authority.governor().inspect()?;
    assert_eq!(
        governor_after.outstanding_total(),
        governor_before.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(
            governor_after.usage(dimension),
            governor_before.usage(dimension)
        );
        assert_eq!(
            governor_after.recovery_shared_usage(dimension),
            governor_before.recovery_shared_usage(dimension)
        );
    }

    let after_snapshot = active.snapshot()?;
    assert_eq!(
        after_snapshot
            .blocks()
            .iter()
            .filter(|block| block.segment_id() == mixed_segment)
            .count(),
        2
    );
    let after_scan = store.scan(
        authority.governor(),
        tenant,
        &after_snapshot,
        LogScan::all(ScanLimit::new(16)?),
    )?;
    let actual = after_scan
        .records()
        .iter()
        .map(|record| {
            (
                record.record().clone(),
                record.commit_position(),
                record.record_ordinal(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    drop(after_scan);
    drop(after_snapshot);
    drop(active);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let restarted_snapshot = reopened.snapshot()?;
    assert_eq!(
        restarted_snapshot
            .blocks()
            .iter()
            .filter(|block| block.segment_id() == mixed_segment)
            .count(),
        2
    );
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &restarted_snapshot,
        LogScan::all(ScanLimit::new(16)?),
    )?;
    let restarted_actual = restarted
        .records()
        .iter()
        .map(|record| {
            (
                record.record().clone(),
                record.commit_position(),
                record.record_ordinal(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(restarted_actual, expected);
    Ok(())
}
