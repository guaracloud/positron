use super::*;

#[test]
fn recovered_frontier_ignores_restart_wall_and_advances_only_by_new_monotonic_elapsed()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(9)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x94; 32]));
    let reserve = || -> Result<_, Box<dyn Error>> {
        Ok(authority.governor().reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?)
    };
    let (first_time, first_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(10_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &first_time,
        &catalog,
        scope,
        key(),
    )?;
    let first = ledger.begin_store_block(reserve()?, StoreBlockIdentity::new([0x95; 16])?)?;
    let first_ingest = first.ingest_time();
    ledger.append(first.finish(b"first".to_vec())?)?;
    first_elapsed.advance(2_000_000_000)?;
    let second = ledger.begin_store_block(reserve()?, StoreBlockIdentity::new([0x98; 16])?)?;
    let second_ingest = second.ingest_time();
    assert!(second_ingest > first_ingest);
    ledger.append(second.finish(b"second".to_vec())?)?;
    drop(ledger);

    let (restarted_time, restarted_elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(i64::MAX / 2));
    let restarted = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &restarted_time,
        &catalog,
        scope,
        key(),
    )?;
    let persisted_frontier_generation = catalog.pin()?.number();
    let after_restart =
        restarted.begin_store_block(reserve()?, StoreBlockIdentity::new([0x96; 16])?)?;
    assert_eq!(after_restart.ingest_time(), second_ingest);
    assert_eq!(catalog.pin()?.number(), persisted_frontier_generation);
    drop(after_restart);
    restarted_elapsed.advance(1_000_000_000)?;
    let advanced = restarted.begin_store_block(reserve()?, StoreBlockIdentity::new([0x97; 16])?)?;
    assert_eq!(
        advanced.ingest_time().instant().value(),
        second_ingest.instant().value() + 1_000_000_000
    );
    assert_eq!(catalog.pin()?.number(), persisted_frontier_generation);
    Ok(())
}

#[test]
fn retention_buckets_use_only_authoritative_kernel_preparation_time() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa6; 16])?,
        CatalogSecret::from_owned(Box::new([0xa7; 32]), Box::new([0xa8; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(29)?);
    let (retention_time, elapsed) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(12_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa9; 32])),
    )?;
    let duration = NonZeroU64::new(10).ok_or("bucket duration")?;
    let first = ledger
        .begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new([0xaa; 16])?,
        )?
        .ingest_time();
    elapsed.advance(7_999_999_999)?;
    let same = ledger
        .begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new([0xab; 16])?,
        )?
        .ingest_time();
    elapsed.advance(1)?;
    let next = ledger
        .begin_store_block(
            preparation_capacity(&authority, tenant)?,
            StoreBlockIdentity::new([0xac; 16])?,
        )?
        .ingest_time();

    let bucket = RetentionBucket::for_ingest_time(tenant, SignalKind::Logs, first, duration)?;
    assert_eq!(
        bucket,
        RetentionBucket::for_ingest_time(tenant, SignalKind::Logs, same, duration)?
    );
    assert_ne!(
        bucket,
        RetentionBucket::for_ingest_time(tenant, SignalKind::Logs, next, duration)?
    );
    assert_eq!(bucket.start(), UnixNanoseconds::new(10_000_000_000));
    assert_eq!(bucket.end_exclusive(), UnixNanoseconds::new(20_000_000_000));
    Ok(())
}

#[test]
fn retention_policy_evidence_is_required_at_admission_and_commit() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xb1; 16])?,
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(19)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(2_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )?;
    let policy = CatalogObject::new(governance_policy([0xb1; 16], tenant, 1))?;
    let policy_identity = policy.identity();
    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(policy);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb5; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;

    let basis = catalog.pin()?;
    let objects = basis
        .object_identities()
        .filter(|identity| *identity != policy_identity)
        .map(|identity| {
            CatalogObject::new(
                basis
                    .object(identity)?
                    .ok_or_else(|| "Catalog policy fixture disappeared".to_owned())?
                    .to_vec(),
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb6; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let missing_generation = catalog.pin()?.identity();
    let baseline = authority.governor().inspect()?;
    let missing = match ledger.begin_retention() {
        Ok(_) => return Err("missing policy evidence admitted retention".into()),
        Err(failure) => failure,
    };
    assert_eq!(missing.code(), LedgerFailureCode::StaleGeneration);
    assert_eq!(catalog.pin()?.identity(), missing_generation);
    let after_missing = authority.governor().inspect()?;
    assert_eq!(
        after_missing.outstanding_total(),
        baseline.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(after_missing.usage(dimension), baseline.usage(dimension));
    }

    let basis = catalog.pin()?;
    let mut objects = basis
        .plaintext_objects()
        .map(|bytes| CatalogObject::new(bytes.to_vec()))
        .collect::<Result<Vec<_>, _>>()?;
    objects.push(CatalogObject::new(governance_policy(
        [0xb1; 16], tenant, 1,
    ))?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb7; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let evaluation = ledger.begin_retention()?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .filter(|identity| *identity != policy_identity)
        .map(|identity| {
            CatalogObject::new(
                basis
                    .object(identity)?
                    .ok_or_else(|| "Catalog policy fixture disappeared".to_owned())?
                    .to_vec(),
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(CatalogObject::new(governance_policy(
        [0xb1; 16], tenant, 2,
    ))?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xb8; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let replaced_generation = catalog.pin()?.identity();
    let stale = evaluation
        .commit()
        .expect_err("policy replacement after admission cannot retire segments");
    assert_eq!(stale.code(), LedgerFailureCode::StaleGeneration);
    assert_eq!(catalog.pin()?.identity(), replaced_generation);
    assert!(ledger.snapshot()?.blocks().is_empty());
    let after_commit = authority.governor().inspect()?;
    assert_eq!(
        after_commit.outstanding_total(),
        baseline.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(after_commit.usage(dimension), baseline.usage(dimension));
    }
    Ok(())
}

#[test]
fn retention_rejects_mismatched_or_duplicate_canonical_policy_without_mutation()
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
    let other_tenant = TenantId::from_bytes([0x65; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(39)?);
    let (retention_time, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(2_000_000_000));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )?;
    install_governance_policy(&catalog, instance, other_tenant, 1, 0xe5)?;
    let mismatched_generation = catalog.pin()?.identity();
    let baseline = authority.governor().inspect()?;

    let mismatch = match ledger.begin_retention() {
        Ok(_) => return Err("another tenant's policy admitted retention".into()),
        Err(failure) => failure,
    };
    assert_eq!(mismatch.code(), LedgerFailureCode::PhysicalScopeMismatch);
    assert_eq!(catalog.pin()?.identity(), mismatched_generation);
    assert!(ledger.snapshot()?.blocks().is_empty());
    let after_mismatch = authority.governor().inspect()?;
    assert_eq!(
        after_mismatch.outstanding_total(),
        baseline.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(after_mismatch.usage(dimension), baseline.usage(dimension));
    }

    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?;
            (!bytes.starts_with(b"POSGOV")).then(|| CatalogObject::new(bytes.to_vec()).ok())?
        })
        .collect::<Vec<_>>();
    objects.push(CatalogObject::new(governance_policy(
        instance.to_bytes(),
        tenant,
        1,
    ))?);
    objects.push(CatalogObject::new(governance_policy(
        instance.to_bytes(),
        tenant,
        2,
    ))?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0xe6; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let duplicate_generation = catalog.pin()?.identity();
    let duplicate = match ledger.begin_retention() {
        Ok(_) => return Err("duplicate canonical policies admitted retention".into()),
        Err(failure) => failure,
    };
    assert_eq!(duplicate.code(), LedgerFailureCode::IntegrityCorruption);
    assert_eq!(catalog.pin()?.identity(), duplicate_generation);
    assert!(ledger.snapshot()?.blocks().is_empty());
    let after_duplicate = authority.governor().inspect()?;
    assert_eq!(
        after_duplicate.outstanding_total(),
        baseline.outstanding_total()
    );
    for dimension in ResourceDimension::ALL {
        assert_eq!(after_duplicate.usage(dimension), baseline.usage(dimension));
    }
    Ok(())
}
