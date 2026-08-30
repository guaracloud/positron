use super::*;

#[test]
fn retention_policy_requires_a_positive_duration() {
    let failure = LogRetentionPolicy::new(0).expect_err("zero retention is not meaningful");
    assert_eq!(
        failure.code(),
        positron_signals::LogStoreFailureCode::InvalidInput
    );
    assert_eq!(
        LogRetentionPolicy::new(7)
            .expect("positive retention")
            .retention_seconds(),
        7
    );
    assert_eq!(
        LogRetentionPolicy::new(u64::MAX)
            .expect_err("retention duration must fit the representable timestamp range")
            .code(),
        positron_signals::LogStoreFailureCode::InvalidInput
    );
}

#[test]
fn retention_buckets_are_fixed_by_tenant_store_and_kernel_ingest_time() -> Result<(), Box<dyn Error>>
{
    let policy = LogRetentionPolicy::new(10)?;
    let first_tenant = TenantId::from_bytes([0x41; 16])?;
    let second_tenant = TenantId::from_bytes([0x42; 16])?;
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
    assert_ne!(first, policy.bucket(second_tenant, first_time)?);
    assert_eq!(first.tenant(), first_tenant);
    assert_eq!(first.signal_kind(), SignalKind::Logs);
    assert_eq!(first.start(), UnixNanoseconds::new(10_000_000_000));
    assert_eq!(first.end_exclusive(), UnixNanoseconds::new(20_000_000_000));
    let maximum_time = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
        i64::MAX,
    )))
    .assign_ingest_time()?;
    assert_eq!(
        LogRetentionPolicy::new(1)?
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
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
    )
    .map_err(|failure| format!("open fresh retention ledger: {failure:?}"))?;
    let store = LogStore::new();
    let policy = LogRetentionPolicy::new(1)?;

    let wrong_scope = store
        .enforce_retention(&ledger, &retention_clock(), other_tenant, policy)
        .expect_err("a tenant cannot execute retention for another tenant's ledger");
    assert_eq!(
        wrong_scope.code(),
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
    );

    assert!(ledger.snapshot()?.blocks().is_empty());
    ledger.seal()?;
    let reopened = ActiveSegmentLedger::open_with_clock(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(11)?),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
        &retention_clock(),
    )?;
    let empty_segment = store.enforce_retention(&reopened, &retention_clock(), tenant, policy)?;
    assert_eq!(empty_segment.expired_segments(), 1);
    assert_eq!(empty_segment.reclaimed_segments(), 1);
    Ok(())
}
