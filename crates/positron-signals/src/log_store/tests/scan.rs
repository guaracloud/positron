use super::*;
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkClass, WorkKind};

#[test]
fn bounded_scan_holds_query_capacity_and_decodes_only_the_result_limit()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x79; 16])?,
        CatalogSecret::from_owned(Box::new([0x7a; 32]), Box::new([0x7b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(79)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let records = (0..1_024)
        .map(|_| minimal_record("bounded", 1))
        .collect::<Result<Vec<_>, _>>()?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    ledger.append(
        LogStore::new()
            .prepare(
                &clock(123),
                tenant,
                shard,
                StoreBlockIdentity::new([0x7c; 16])?,
                records,
            )?
            .into_store_block(),
    )?;
    let snapshot = ledger.snapshot()?;
    let before = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(!result.complete());
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before + 1
    );
    drop(result);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        before
    );
    Ok(())
}

#[test]
fn insufficient_query_budget_refuses_before_decode_and_releases_on_error()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x7d; 16])?,
        CatalogSecret::from_owned(Box::new([0x7e; 32]), Box::new([0x7f; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(80)?);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x7f; 16])?,
        b"malformed-but-authenticated".to_vec(),
    )?)?;
    let snapshot = ledger.snapshot()?;
    let baseline = authority
        .governor()
        .inspect()?
        .outstanding_for(WorkClass::InteractiveQueryTail);
    let claim = WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?;
    let mut saturation = Vec::new();
    while let Ok(grant) = authority.governor().reserve(claim) {
        saturation.push(grant);
    }
    let failure = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("query admission must precede malformed-block decoding");
    assert_eq!(
        failure.code(),
        LogStoreFailureCode::ResourceAdmissionRefused
    );
    drop(saturation);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    let malformed = LogStore::new()
        .scan(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
        )
        .expect_err("malformed authenticated bytes fail closed");
    assert_eq!(malformed.code(), LogStoreFailureCode::MalformedBlock);
    assert_eq!(
        authority
            .governor()
            .inspect()?
            .outstanding_for(WorkClass::InteractiveQueryTail),
        baseline
    );
    Ok(())
}
