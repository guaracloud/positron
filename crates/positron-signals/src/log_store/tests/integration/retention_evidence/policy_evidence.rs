use super::*;

#[test]
fn retention_authenticates_each_encoded_record_time_against_its_kernel_block()
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
    let retention_time = RetentionTimeAuthority::establish()?;
    let key = || SegmentProtectionKey::from_owned(Box::new([0xe4; 32]));
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the authenticated-time fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let source_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(29)?);
    let source = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        source_scope,
        key(),
    )?;
    source.append(
        store
            .prepare(
                source.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0xe5; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    let payload = source.snapshot()?.blocks()[0].payload().to_vec();
    source.seal()?;

    let target_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(30)?);
    let target = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        target_scope,
        key(),
    )?;
    target.append(
        target
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0xe6; 16])?,
            )?
            .finish(payload)?,
    )?;
    target.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        target_scope,
        key(),
    )?;
    let baseline = authority.governor().inspect()?;
    let policy = retention_policy(&catalog, &active, tenant, 1)?;
    let failure = store
        .enforce_retention(&active, tenant, policy)
        .expect_err("encoded record time must authenticate before retention publication");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::IntegrityCorruption
    );
    assert_eq!(active.snapshot()?.blocks().len(), 1);
    assert_same_resource_usage(&baseline, &authority.governor().inspect()?);
    Ok(())
}

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
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5f; 32])),
    )?;
    ledger.append(
        ledger
            .begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0x6f; 16])?,
            )?
            .finish(vec![0xff])?,
    )?;
    ledger.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5f; 32])),
    )?;

    let policy = retention_policy(&catalog, &active, tenant, 1)?;
    let failure = LogStore::new()
        .enforce_retention(&active, tenant, policy)
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
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed_for_test(
        UnixNanoseconds::new(10_000_000_000),
    );
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
                    vec![record.clone()],
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
    assert_eq!(
        block
            .observe_ingest_time(UnixNanoseconds::new(1_000_000_000))
            .expect_err("observation cannot weaken exact v3 block evidence")
            .code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption,
    );
    let legacy_payload = block.payload().to_vec();
    drop(snapshot);
    let _policy = retention_policy(&catalog, &active, tenant, 1)?;
    let outcome = active
        .begin_retention()?
        .commit()
        .map_err(|failure| format!("retire fresh retention ledger: {failure:?}"))?;
    assert_eq!(outcome.logically_retired_segments(), 0);
    assert_eq!(active.snapshot()?.blocks().len(), 1);
    elapsed.advance(1_000_000_000)?;
    let outcome = active
        .begin_retention()?
        .commit()
        .map_err(|failure| format!("retire elapsed retention ledger: {failure:?}"))?;
    assert_eq!(outcome.logically_retired_segments(), 1);
    assert_eq!(active.snapshot()?.blocks().len(), 0);
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
    let observed = legacy_block.observe_ingest_time(UnixNanoseconds::new(1_000_000_000))?;
    assert_eq!(observed.instant(), UnixNanoseconds::new(1_000_000_000));
    assert_eq!(
        retention_policy(&catalog, &other, tenant, 1)?
            .bucket(tenant, observed)
            .expect_err("legacy observation cannot select a retention bucket")
            .code(),
        positron_signals::LogStoreFailureCode::UnsupportedFormat
    );
    let scanned = store.scan(
        authority.governor(),
        tenant,
        &legacy_snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(scanned.records().len(), 1);
    assert_eq!(
        retention_policy(&catalog, &other, tenant, 1)?
            .bucket(tenant, scanned.records()[0].ingest_time())
            .expect_err("production legacy scan time remains retention-unavailable")
            .code(),
        positron_signals::LogStoreFailureCode::UnsupportedFormat
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
        .enforce_retention(
            &legacy,
            tenant,
            retention_policy(&catalog, &legacy, tenant, 1)?,
        )
        .expect_err("unauthenticated ingest-time metadata cannot drive public retention");
    assert_eq!(
        refusal.code(),
        positron_signals::LogStoreFailureCode::UnsupportedFormat
    );
    assert_eq!(legacy.snapshot()?.blocks().len(), 1);
    Ok(())
}
