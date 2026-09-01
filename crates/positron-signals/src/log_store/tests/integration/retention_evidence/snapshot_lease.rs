use super::*;

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
    let retention_time = RetentionTimeAuthority::establish()?;
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
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
    )?;
    ledger.append(
        store
            .prepare(
                ledger.begin_store_block(
                    preparation_capacity(&authority, tenant)?,
                    StoreBlockIdentity::new([0x6e; 16])?,
                )?,
                vec![record],
            )?
            .into_store_block(),
    )?;
    let leased_payload = ledger.snapshot()?.blocks()[0].payload().to_vec();
    let lifecycle = retention_clock();
    let now = u64::try_from(
        lifecycle
            .assign_ingest_time()?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .ok_or("lifecycle seconds")?,
    )?;
    let lease =
        ledger.create_snapshot_lease_for(now, NonZeroU64::new(100).ok_or("lease duration")?)?;
    let lease_identity = lease.identity();
    drop(lease);
    let PolicyEvaluation::Accepted(large) = IngestPolicy::preserving(1)?.evaluate(
        NativeLogCandidate::new(
            None,
            None,
            Some(CandidateAttributeValue::string("x".repeat(200_000))),
            vec![],
            LogMetadata::empty(),
        ),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving policy rejected the large resume fixture".into());
    };
    let large_record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *large)?;
    for identity in [[0x7e; 16], [0x8e; 16], [0x9e; 16], [0xae; 16]] {
        ledger.append(
            store
                .prepare(
                    ledger.begin_store_block(
                        preparation_capacity(&authority, tenant)?,
                        StoreBlockIdentity::new(identity)?,
                    )?,
                    vec![large_record.clone()],
                )?
                .into_store_block(),
        )?;
    }
    ledger.seal()?;
    std::thread::sleep(std::time::Duration::from_millis(1_050));
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
    )?;
    let outcome = store.enforce_retention(
        &active,
        tenant,
        retention_policy(&catalog, &active, tenant, 1)?,
    )?;
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
    let resume_now = active.snapshot_lease_time()?.max(now + 1);
    let before_resume = authority.governor().inspect()?;
    let resumed = active.resume_snapshot_lease(lease_identity, resume_now)?;
    assert_eq!(resumed.snapshot().blocks().len(), 1);
    assert_eq!(resumed.snapshot().blocks()[0].payload(), leased_payload);
    assert!(segment_path.exists());
    let during_resume = authority.governor().inspect()?;
    assert_eq!(
        during_resume.outstanding_total(),
        before_resume.outstanding_total() + 1
    );
    drop(resumed);
    assert_same_resource_usage(&before_resume, &authority.governor().inspect()?);
    let mut segment = std::fs::read(&segment_path)?;
    let last = segment
        .last_mut()
        .ok_or("retired segment payload is unexpectedly empty")?;
    *last ^= 0xff;
    std::fs::write(&segment_path, segment)?;

    let before = authority.governor().inspect()?;
    let blocker = query_capacity_blocker_leaving(&authority, tenant, 1_100_000)?;
    let blocked = authority.governor().inspect()?;
    let refusal = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("capacity refusal must precede retired segment recovery");
    assert_eq!(
        refusal.code(),
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_same_resource_usage(&blocked, &authority.governor().inspect()?);
    drop(blocker);
    let corrupted = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("corrupted retired payload must remain typed after capacity returns");
    assert_eq!(
        corrupted.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    assert_same_resource_usage(&before, &authority.governor().inspect()?);
    std::fs::remove_file(&segment_path)?;
    std::fs::create_dir(&segment_path)?;
    let substituted = active
        .resume_snapshot_lease(lease_identity, resume_now)
        .expect_err("a retired segment directory substitution must fail before decode");
    assert_eq!(
        substituted.code(),
        positron_kernel::LedgerFailureCode::IntegrityCorruption
    );
    assert_same_resource_usage(&before, &authority.governor().inspect()?);
    Ok(())
}
