use super::*;

#[test]
fn governance_retention_duration_must_fit_the_ingest_time_domain() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0xa1; 16])?,
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(14)?),
        SegmentProtectionKey::from_owned(Box::new([0xa4; 32])),
    )?;
    let first_unrepresentable_second = (i64::MAX as u64 / 1_000_000_000) + 1;
    let failure = retention_policy(&catalog, &ledger, tenant, first_unrepresentable_second)
        .expect_err("POSGOV03 cannot authorize a duration outside the timestamp domain");
    let failure = failure
        .downcast_ref::<positron_signals::LogStoreFailure>()
        .ok_or("retention policy failure lost its public type")?;
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::InvalidInput
    );
    Ok(())
}

#[test]
fn retention_buckets_are_fixed_by_tenant_store_and_kernel_ingest_time() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x0e; 16])?,
        CatalogSecret::from_owned(Box::new([0x0f; 32]), Box::new([0x10; 32])),
    )?;
    let first_tenant = TenantId::from_bytes([0x41; 16])?;
    let second_tenant = TenantId::from_bytes([0x42; 16])?;
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(first_tenant, SignalKind::Logs, VirtualShardId::new(10)?),
        SegmentProtectionKey::from_owned(Box::new([0x11; 32])),
    )?;
    let policy = retention_policy(&catalog, &ledger, first_tenant, 10)?;
    let first_time = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        12_000_000_000,
    )))
    .assign_ingest_time()?;
    let same_bucket_time = LifecycleClock::new(FixedLifecycleClockSource::new(
        UnixNanoseconds::new(19_999_999_999),
    ))
    .assign_ingest_time()?;
    let next_bucket_time = LifecycleClock::new(FixedLifecycleClockSource::new(
        UnixNanoseconds::new(20_000_000_000),
    ))
    .assign_ingest_time()?;

    let first = policy.bucket(first_tenant, first_time)?;
    assert_eq!(first, policy.bucket(first_tenant, same_bucket_time)?);
    assert_ne!(first, policy.bucket(first_tenant, next_bucket_time)?);
    assert_eq!(
        policy
            .bucket(second_tenant, first_time)
            .expect_err("a policy is bound to its tenant")
            .code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );
    assert_eq!(first.tenant(), first_tenant);
    assert_eq!(first.signal_kind(), SignalKind::Logs);
    assert_eq!(first.start(), UnixNanoseconds::new(10_000_000_000));
    assert_eq!(first.end_exclusive(), UnixNanoseconds::new(20_000_000_000));
    let maximum_time = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        i64::MAX,
    )))
    .assign_ingest_time()?;
    assert_eq!(
        policy
            .bucket(first_tenant, maximum_time)
            .expect_err("a bucket ending beyond the timestamp domain must fail")
            .code(),
        positron_signals::LogStoreFailureCode::LimitExceeded
    );
    Ok(())
}

#[test]
fn retention_refuses_wrong_scope_before_mutation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1b; 16])?,
        CatalogSecret::from_owned(Box::new([0x2b; 32]), Box::new([0x3b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let other_tenant = TenantId::from_bytes([0x42; 16])?;
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
    )
    .map_err(|failure| format!("open fresh retention ledger: {failure:?}"))?;
    let store = LogStore::new();
    let policy = retention_policy(&catalog, &ledger, tenant, 1)?;

    let wrong_scope = store
        .enforce_retention(&ledger, other_tenant, policy)
        .expect_err("a tenant cannot execute retention for another tenant's ledger");
    assert_eq!(
        wrong_scope.code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );

    assert!(ledger.snapshot()?.blocks().is_empty());
    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
    )?;
    let empty_segment = store.enforce_retention(&reopened, tenant, policy)?;
    assert_eq!(empty_segment.expired_segments(), 1);
    assert_eq!(empty_segment.reclaimed_segments(), 1);
    Ok(())
}

#[test]
fn retention_refuses_a_policy_removed_from_the_current_catalog_before_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(12)?),
        SegmentProtectionKey::from_owned(Box::new([0x65; 32])),
    )?;
    let policy = retention_policy(&catalog, &ledger, tenant, 1)?;
    let basis = catalog.pin()?;
    let objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?;
            (!bytes.starts_with(b"POSGOV03")).then(|| CatalogObject::new(bytes.to_vec()).ok())?
        })
        .collect::<Vec<_>>();
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x66; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let generation = catalog.pin()?.identity();
    let capacity = authority.governor().inspect()?;

    let failure = LogStore::new()
        .enforce_retention(&ledger, tenant, policy)
        .expect_err("a removed governance object cannot authorize deletion");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::IntegrityCorruption
    );
    assert_eq!(catalog.pin()?.identity(), generation);
    assert_same_resource_usage(&capacity, &authority.governor().inspect()?);
    Ok(())
}

#[test]
fn retention_refuses_a_stale_policy_after_valid_governance_replacement()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let instance = InstanceId::new([0x67; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x68; 32]), Box::new([0x69; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(16)?),
        SegmentProtectionKey::from_owned(Box::new([0x6a; 32])),
    )?;
    let stale = retention_policy(&catalog, &ledger, tenant, 1)?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .filter_map(|identity| {
            let bytes = basis.object(identity).ok().flatten()?;
            (!bytes.starts_with(b"POSGOV03")).then(|| CatalogObject::new(bytes.to_vec()).ok())?
        })
        .collect::<Vec<_>>();
    objects.push(CatalogObject::new(governance_fixture(
        instance.to_bytes(),
        tenant,
        2,
    )?)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([0x6b; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    let generation = catalog.pin()?.identity();
    let capacity = authority.governor().inspect()?;
    let failure = LogStore::new()
        .enforce_retention(&ledger, tenant, stale)
        .expect_err("a replaced governance payload invalidates the captured policy");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::IntegrityCorruption
    );
    assert_eq!(catalog.pin()?.identity(), generation);
    assert!(ledger.snapshot()?.blocks().is_empty());
    assert_same_resource_usage(&capacity, &authority.governor().inspect()?);
    Ok(())
}

fn governance_fixture(
    instance: [u8; 16],
    tenant: TenantId,
    retention_seconds: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let intent = InitialTenantIntent::new(
        instance,
        tenant,
        TenantSlug::parse_canonical("retention-test")?,
        "Retention test tenant",
        PrincipalId::from_bytes([0x11; 16])?,
        [0x21; 32],
        [0x22; 32],
        PrincipalId::from_bytes([0x12; 16])?,
        [0x23; 32],
        [0x24; 32],
        PrincipalId::from_bytes([0x13; 16])?,
        [0x25; 32],
        [0x26; 32],
        [0x27; 32],
        [0x28; 32],
        vec![0x29],
        vec![0x2a],
        retention_seconds,
        1,
        1,
        [1; 11],
        InitialAuditContext::new(1, [0x2b; 16], true)?,
    )?;
    Ok(InitialGovernanceIntent::create_tenant(intent)?
        .into_parts()
        .0)
}

#[test]
fn log_preparation_refuses_a_non_log_kernel_scope_without_additional_mutation()
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
    let retention_time = RetentionTimeAuthority::establish()?;
    let traces = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(13)?),
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )?;
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the cross-signal fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let capacity = authority.governor().inspect()?;
    let preparation = traces.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x75; 16])?,
    )?;
    let generation = catalog.pin()?.identity();

    let failure = match LogStore::new().prepare(preparation, vec![record]) {
        Ok(_) => return Err("Log Store accepted a preparation minted for Traces".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );
    assert_eq!(catalog.pin()?.identity(), generation);
    assert_same_resource_usage(&capacity, &authority.governor().inspect()?);
    Ok(())
}
