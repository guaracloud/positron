use super::*;

#[cfg(feature = "test-support")]
#[test]
fn preparation_authority_rejects_wrong_capacity_and_production_time_substitution()
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
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(13)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(300));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    let wrong_capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    let failure =
        match ledger.begin_store_block(wrong_capacity, StoreBlockIdentity::new([0xe5; 16])?) {
            Ok(_) => return Err("query capacity authorized ingest preparation".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);

    let foreign_root = TemporaryRoot::new()?;
    let foreign_volume =
        PrimaryDataVolume::acquire(foreign_root.path(), MountQualification::LocalHost)?;
    let foreign_authority = establish_authority(foreign_volume)?;
    let local_baseline = authority.governor().inspect()?.outstanding_total();
    let foreign_baseline = foreign_authority.governor().inspect()?.outstanding_total();
    let generation_before_foreign = catalog.pin()?.number();
    let foreign_capacity = preparation_capacity(&foreign_authority, tenant)?;
    let failure =
        match ledger.begin_store_block(foreign_capacity, StoreBlockIdentity::new([0xe8; 16])?) {
            Ok(_) => return Err("foreign governor authorized frontier publication".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    assert_eq!(catalog.pin()?.number(), generation_before_foreign);
    assert!(
        catalog
            .pin()?
            .plaintext_objects()
            .all(|bytes| !bytes.starts_with(b"PRETFR01"))
    );
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        local_baseline
    );
    assert_eq!(
        foreign_authority.governor().inspect()?.outstanding_total(),
        foreign_baseline
    );

    let failure = match ledger.begin_store_block_for_test(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xe6; 16])?,
        &retention_time,
    ) {
        Ok(_) => return Err("production retention time entered test-only path".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);

    let test_time = RetentionTimeAuthority::for_test_ingest_time(UnixNanoseconds::new(301));
    let wrong_capacity = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?;
    let failure = match ledger.begin_store_block_for_test(
        wrong_capacity,
        StoreBlockIdentity::new([0xe7; 16])?,
        &test_time,
    ) {
        Ok(_) => return Err("query capacity authorized test preparation".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    Ok(())
}

#[cfg(feature = "test-support")]
#[test]
fn test_ingest_time_authority_cannot_publish_retention_evidence() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xe9; 16])?,
        CatalogSecret::from_owned(Box::new([0xea; 32]), Box::new([0xeb; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(24)?);
    let test_time = RetentionTimeAuthority::for_test_ingest_time(UnixNanoseconds::new(301));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &test_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xec; 32])),
    )?;
    let generation = catalog.pin()?.identity();
    let capacity = authority.governor().inspect()?;

    let failure = match ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xed; 16])?,
    ) {
        Ok(_) => return Err("test-only time minted retained preparation evidence".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::UnsupportedFormat);
    assert_eq!(catalog.pin()?.identity(), generation);
    assert!(
        catalog
            .pin()?
            .plaintext_objects()
            .all(|bytes| !bytes.starts_with(b"PRETFR01"))
    );
    let after = authority.governor().inspect()?;
    assert_eq!(after.outstanding_total(), capacity.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), capacity.usage(dimension));
    }
    assert!(ledger.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn retention_evaluation_cannot_commit_after_concurrent_append_uncertainty()
-> Result<(), Box<dyn Error>> {
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
    let basis = catalog.pin()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xc4; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance_policy(
                instance.to_bytes(),
                tenant,
                1,
            ))?],
        )?,
        None,
    )?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(25)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(2_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xc5; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let prepared = ledger
        .begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new([0xc6; 16])?,
        )?
        .finish(b"uncertain append".to_vec())?;
    let evaluation = ledger.begin_retention()?;
    let generation = catalog.pin()?.identity();

    let append = with_ledger_fault(LedgerFileEvent::SynchronizeFrame, || {
        ledger.append(prepared)
    })
    .expect_err("frame synchronization uncertainty must fence the ledger");
    assert_eq!(
        append.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    let retention = evaluation
        .commit()
        .expect_err("a stale evaluation cannot bypass the recovery fence");
    assert_eq!(retention.code(), LedgerFailureCode::RecoveryRequired);
    assert_eq!(catalog.pin()?.identity(), generation);
    drop(ledger);

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

#[test]
fn stale_evaluation_cannot_regress_a_newly_published_scope_frontier() -> Result<(), Box<dyn Error>>
{
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
    let basis = catalog.pin()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd4; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance_policy(
                instance.to_bytes(),
                tenant,
                1,
            ))?],
        )?,
        None,
    )?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(26)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(1_000_000_000));
    let key = || SegmentProtectionKey::from_owned(Box::new([0xd5; 32]));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let stale = ledger.begin_retention()?;
    elapsed.advance(1_000_000_000)?;
    let newer = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xd6; 16])?,
    )?;
    assert_eq!(
        newer.ingest_time().instant(),
        UnixNanoseconds::new(2_000_000_000)
    );
    drop(newer);
    let generation = catalog.pin()?.identity();

    let failure = stale
        .commit()
        .expect_err("retention cannot republish an older per-scope frontier");
    assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);
    assert_eq!(catalog.pin()?.identity(), generation);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let recovered = reopened.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xd7; 16])?,
    )?;
    assert_eq!(
        recovered.ingest_time().instant(),
        UnixNanoseconds::new(2_000_000_000)
    );
    Ok(())
}

#[test]
fn retention_bounds_and_pinned_evaluations_fail_closed_without_capacity_drift()
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
    install_governance_policy(&catalog, instance, tenant, u64::MAX, 0xf7)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(14)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(20_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xf4; 32])),
    )?;

    let failure = match ledger.begin_retention() {
        Ok(_) => return Err("overflowing retention duration was admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);

    install_governance_policy(&catalog, instance, tenant, 1, 0xf8)?;

    let prepared = ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0xf5; 16])?,
    )?;
    let stale_blocks = ledger.begin_retention()?;
    ledger.append(prepared.finish(b"later".to_vec())?)?;
    assert_eq!(
        stale_blocks
            .commit()
            .expect_err("evaluation must pin the inspected blocks")
            .code(),
        LedgerFailureCode::StaleGeneration
    );

    let unrelated_catalog = ledger.begin_retention()?;
    let basis = catalog.pin()?;
    let objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xf6; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let outcome = unrelated_catalog.commit()?;
    assert_eq!(outcome.logically_retired_segments(), 0);
    Ok(())
}

#[test]
fn monotonic_overflow_and_cutoff_underflow_are_typed_public_refusals() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let instance = InstanceId::new([0x71; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    install_governance_policy(&catalog, instance, tenant, 1, 0x77)?;

    let (overflow_time, overflow_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX));
    let overflow_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(15)?);
    let overflow_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &overflow_time,
        &catalog,
        overflow_scope,
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    let initial = overflow_ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x74; 16])?,
    )?;
    assert_eq!(
        initial.ingest_time().instant(),
        UnixNanoseconds::new(i64::MAX)
    );
    drop(initial);
    overflow_elapsed.advance(1)?;
    let failure = match overflow_ledger.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x75; 16])?,
    ) {
        Ok(_) => return Err("monotonic overflow minted Ingest Time".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    let failure = match overflow_ledger.begin_retention() {
        Ok(_) => return Err("monotonic overflow authorized retention".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    assert_eq!(
        format!("{overflow_time:?}"),
        "RetentionTimeAuthority { <monotonic> }"
    );

    let (minimum_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MIN));
    let minimum_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &minimum_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(16)?),
        SegmentProtectionKey::from_owned(Box::new([0x76; 32])),
    )?;
    let failure = match minimum_ledger.begin_retention() {
        Ok(_) => return Err("underflowing retention cutoff was admitted".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    Ok(())
}
