use super::*;

#[test]
fn generic_lifecycle_clock_cannot_authorize_a_retention_bucket() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let retention_time = RetentionTimeAuthority::establish()?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(18)?),
        SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
    )?;
    let policy = retention_policy(&catalog, &ledger, tenant, 10)?;
    let unretained = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        12_000_000_000,
    )))
    .assign_ingest_time()?;

    assert_eq!(
        policy
            .bucket(tenant, unretained)
            .expect_err("a generic clock cannot authorize destructive retention")
            .code(),
        positron_signals::LogStoreFailureCode::UnsupportedFormat,
    );
    Ok(())
}

#[test]
fn legacy_governance_identity_remains_readable_but_cannot_authorize_retention()
-> Result<(), Box<dyn Error>> {
    for (version, transaction, shard) in [(1_u8, 0x95, 30), (2_u8, 0x96, 31)] {
        let root = TemporaryRoot::new()?;
        let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
        let authority = establish_kernel_authority(volume)?;
        let instance = InstanceId::new([0x91; 16])?;
        let catalog = Catalog::open(
            &authority,
            instance,
            CatalogSecret::from_owned(Box::new([0x97; 32]), Box::new([0x98; 32])),
        )?;
        let tenant = TenantId::from_bytes([0x41; 16])?;
        let basis = catalog.pin()?;
        let committed = catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([transaction; 16])?,
                FormatEpoch::CATALOG_V1,
                vec![CatalogObject::new(legacy_governance_fixture(
                    version,
                    instance.to_bytes(),
                    tenant,
                ))?],
            )?,
            None,
        )?;
        positron_governance::Identity::open(committed.snapshot())?;
        assert_eq!(
            LogRetentionPolicy::from_catalog(committed.snapshot())
                .expect_err("legacy identity cannot mint retention policy evidence")
                .code(),
            positron_signals::LogStoreFailureCode::IntegrityCorruption,
        );
        let retention_time = RetentionTimeAuthority::establish()?;
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(shard)?),
            SegmentProtectionKey::from_owned(Box::new([0x99; 32])),
        )?;
        let generation = catalog.pin()?.identity();
        let failure = match ledger.begin_retention() {
            Ok(_) => return Err("legacy policy admitted destructive retention".into()),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.code(),
            positron_kernel::LedgerFailureCode::UnsupportedFormat
        );
        assert_eq!(catalog.pin()?.identity(), generation);
    }
    Ok(())
}

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
    let preparation = ledger.begin_store_block(
        preparation_capacity(&authority, first_tenant)?,
        StoreBlockIdentity::new([0x12; 16])?,
    )?;
    let first_time = preparation.ingest_time();
    drop(preparation);
    let first = policy.bucket(first_tenant, first_time)?;
    assert_eq!(
        policy
            .bucket(second_tenant, first_time)
            .expect_err("a policy is bound to its tenant")
            .code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );
    assert_eq!(first.tenant(), first_tenant);
    assert_eq!(first.signal_kind(), SignalKind::Logs);
    assert_eq!(
        first.end_exclusive().value() - first.start().value(),
        10_000_000_000,
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

pub(super) fn governance_fixture(
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

fn legacy_governance_fixture(version: u8, instance: [u8; 16], tenant: TenantId) -> Vec<u8> {
    let mut encoded = b"POSGOV01".to_vec();
    encoded.extend_from_slice(&instance);
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.push(7);
    encoded.extend_from_slice(b"default");
    encoded.push(14);
    encoded.extend_from_slice(b"Default tenant");
    encoded.extend_from_slice(&[3; 16]);
    encoded.extend_from_slice(&[4; 32]);
    encoded.extend_from_slice(&[5; 32]);
    if version == 2 {
        encoded[..8].copy_from_slice(b"POSGOV02");
        encoded.extend_from_slice(&[12; 16]);
        encoded.extend_from_slice(&[13; 32]);
        encoded.extend_from_slice(&[14; 32]);
    }
    encoded.extend_from_slice(&[6; 32]);
    encoded.extend_from_slice(&[7; 32]);
    encoded.extend_from_slice(&64_u16.to_be_bytes());
    encoded.extend_from_slice(&[8; 64]);
    encoded.extend_from_slice(&48_u16.to_be_bytes());
    encoded.extend_from_slice(&[9; 48]);
    encoded.extend_from_slice(&2_592_000_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..11 {
        encoded.extend_from_slice(&10_u64.to_be_bytes());
    }
    encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
    encoded
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
