use super::*;

#[test]
fn first_retired_artifact_cleanup_failure_fences_the_live_ledger() -> Result<(), Box<dyn Error>> {
    with_expired_segment_fixture(0x81, 21, |fixture| {
        let paths = segment_artifact_paths(fixture.root.path(), fixture.segment);
        std::fs::remove_file(&paths.sealed_segment)?;
        std::fs::create_dir(&paths.sealed_segment)?;
        let failure = fixture
            .store
            .enforce_retention(fixture.ledger, fixture.tenant, fixture.policy)
            .expect_err("a directory cannot be reclaimed as a segment file");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert_recovery_fenced(fixture.ledger)?;
        assert!(paths.sealed_segment.is_dir());
        assert!(paths.sealed_frontier.is_file());
        Ok(())
    })
}

#[test]
fn cleanup_catalog_refusal_after_unlink_fences_the_committed_retirement()
-> Result<(), Box<dyn Error>> {
    with_expired_segment_fixture(0x82, 22, |fixture| {
        let paths = segment_artifact_paths(fixture.root.path(), fixture.segment);
        let failure = with_catalog_publication_fault_after(
            CatalogPublicationFault::SynchronizeCommit,
            1,
            || {
                fixture
                    .store
                    .enforce_retention(fixture.ledger, fixture.tenant, fixture.policy)
            },
        )
        .expect_err("cleanup Catalog refusal follows committed logical and physical mutation");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert!(!paths.sealed_segment.exists());
        assert!(!paths.sealed_frontier.exists());
        assert_recovery_fenced(fixture.ledger)?;
        Ok(())
    })
}

#[test]
fn frontier_cleanup_failure_after_segment_unlink_requires_recovery() -> Result<(), Box<dyn Error>> {
    with_expired_segment_fixture(0x83, 23, |fixture| {
        let paths = segment_artifact_paths(fixture.root.path(), fixture.segment);
        std::fs::remove_file(&paths.sealed_frontier)?;
        std::fs::create_dir(&paths.sealed_frontier)?;
        let failure = fixture
            .store
            .enforce_retention(fixture.ledger, fixture.tenant, fixture.policy)
            .expect_err("frontier directory substitution follows segment unlink");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert!(!paths.sealed_segment.exists());
        assert!(paths.sealed_frontier.is_dir());
        assert_recovery_fenced(fixture.ledger)?;
        Ok(())
    })
}

#[test]
fn active_alias_of_a_retired_segment_fails_closed_without_deleting_the_source()
-> Result<(), Box<dyn Error>> {
    with_expired_segment_fixture(0x84, 24, |fixture| {
        let paths = segment_artifact_paths(fixture.root.path(), fixture.segment);
        std::fs::copy(&paths.sealed_segment, &paths.active_segment)?;
        let failure = fixture
            .store
            .enforce_retention(fixture.ledger, fixture.tenant, fixture.policy)
            .expect_err("a retired identifier cannot also exist in the active directory");
        assert_eq!(
            failure.code(),
            positron_signals::LogStoreFailureCode::IntegrityCorruption
        );
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert!(paths.sealed_segment.is_file());
        assert!(paths.sealed_frontier.is_file());
        assert!(paths.active_segment.is_file());
        Ok(())
    })
}

struct ExpiredSegmentFixture<'fixture, 'kernel, 'catalog> {
    root: &'fixture TemporaryRoot,
    store: &'fixture LogStore,
    ledger: &'fixture ActiveSegmentLedger<'kernel, 'catalog>,
    tenant: TenantId,
    segment: positron_kernel::SegmentId,
    policy: LogRetentionPolicy,
}

fn assert_recovery_fenced(ledger: &ActiveSegmentLedger<'_, '_>) -> Result<(), Box<dyn Error>> {
    let failure = match ledger.snapshot() {
        Ok(_) => return Err("post-Catalog cleanup failure did not fence snapshots".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        failure.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    Ok(())
}

fn with_expired_segment_fixture(
    discriminator: u8,
    shard: u32,
    test: impl FnOnce(ExpiredSegmentFixture<'_, '_, '_>) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([discriminator; 16])?,
        CatalogSecret::from_owned(
            Box::new([discriminator.wrapping_add(1); 32]),
            Box::new([discriminator.wrapping_add(2); 32]),
        ),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(shard)?);
    let retention_time = RetentionTimeAuthority::establish()?;
    let store = LogStore::new();
    let PolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(None, None, None, vec![], LogMetadata::empty()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the cleanup fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let protection = || SegmentProtectionKey::from_owned(Box::new([discriminator; 32]));
    let sealed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let segment = sealed.active_segment_id()?;
    sealed.append(
        store
            .prepare(
                sealed.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([discriminator.wrapping_add(3); 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    sealed.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        protection(),
    )?;
    let policy = retention_policy(&catalog, &ledger, tenant, 1)?;
    test(ExpiredSegmentFixture {
        root: &root,
        store: &store,
        ledger: &ledger,
        tenant,
        segment,
        policy,
    })
}

struct SegmentArtifactPaths {
    sealed_segment: std::path::PathBuf,
    sealed_frontier: std::path::PathBuf,
    active_segment: std::path::PathBuf,
}

fn segment_artifact_paths(
    root: &std::path::Path,
    segment: positron_kernel::SegmentId,
) -> SegmentArtifactPaths {
    let name = segment
        .to_bytes()
        .iter()
        .fold(String::with_capacity(32), |mut name, byte| {
            use std::fmt::Write as _;
            write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
            name
        });
    let sealed = root.join("segments/sealed");
    let active = root.join("segments/active");
    SegmentArtifactPaths {
        sealed_segment: sealed.join(format!("{name}.segment")),
        sealed_frontier: sealed.join(format!("{name}.frontier")),
        active_segment: active.join(format!("{name}.segment")),
    }
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
                vec![record.clone()],
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
    let _policy = retention_policy(&catalog, &active, tenant, 1)?;
    let protected = active.snapshot()?;
    assert_eq!(protected.blocks().len(), 2);
    let retired = active.begin_retention()?.commit()?;
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
    let reader = active.reader()?;
    let prepared_after_failure = store
        .prepare(
            active.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                StoreBlockIdentity::new([0x77; 16])?,
            )?,
            vec![record],
        )?
        .into_store_block();
    let policy = retention_policy(&catalog, &active, tenant, 1)?;
    let failure = store
        .enforce_retention(&active, tenant, policy)
        .expect_err("partial physical reclamation cannot be reported as a clean refusal");
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    let poisoned_generation = catalog.pin()?.number();
    let preparation_failure = match active.begin_store_block(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x78; 16])?,
    ) {
        Ok(_) => return Err("kernel preparation bypassed the recovery fence".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        preparation_failure.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    let test_retention_time =
        RetentionTimeAuthority::for_test_ingest_time(UnixNanoseconds::new(1_000_000_000));
    let test_preparation_failure = match active.begin_store_block_for_test(
        preparation_capacity(&authority, tenant)?,
        StoreBlockIdentity::new([0x79; 16])?,
        &test_retention_time,
    ) {
        Ok(_) => return Err("test preparation bypassed the recovery fence".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        test_preparation_failure.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    assert_eq!(catalog.pin()?.number(), poisoned_generation);
    let snapshot_failure = match active.snapshot() {
        Ok(_) => return Err("a partially reclaimed live ledger was not fenced".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        snapshot_failure.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    let reader_failure = match reader.snapshot() {
        Ok(_) => return Err("an existing reader bypassed the fenced ledger".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        reader_failure.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    let retention_failure = match active.begin_retention() {
        Ok(_) => return Err("retention continued on a partially reclaimed live ledger".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        retention_failure.code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    assert_eq!(
        active
            .create_snapshot_lease(1, 2)
            .expect_err("leases cannot continue on a partially reclaimed live ledger")
            .code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
    assert_eq!(
        active
            .append(prepared_after_failure)
            .expect_err("append cannot continue on a partially reclaimed live ledger")
            .code(),
        positron_kernel::LedgerFailureCode::RecoveryRequired
    );
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
    restarted.begin_retention()?.commit()?;
    assert!(!second_path.exists());
    assert_same_resource_usage(&baseline, &authority.governor().inspect()?);
    Ok(())
}
