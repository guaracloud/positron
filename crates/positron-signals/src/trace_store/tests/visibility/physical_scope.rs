use super::super::*;

#[test]
fn trace_scan_enforces_physical_tenant_and_signal_boundaries() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x14; 16])?,
        CatalogSecret::from_owned(Box::new([0x24; 32]), Box::new([0x34; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(4)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Traces, shard),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    let block = TraceStore::new().prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        positron_kernel::StoreBlockIdentity::new([0x64; 16])?,
        vec![SpanObservation::checked_native(
            [0x11; 16],
            [0x22; 8],
            None,
            "server".to_owned(),
            EventTime::missing(),
            EventTime::missing(),
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
            positron_policy::PolicyProvenance::new(1, [0x77; 32], Vec::new()).unwrap(),
        )?],
    )?;
    ledger.append(block.into_store_block())?;
    let snapshot = ledger.snapshot()?;
    let wrong_tenant = TraceStore::new()
        .scan(
            authority.governor(),
            TenantId::from_bytes([0x42; 16])?,
            &snapshot,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("cross-tenant trace scan must fail closed");
    assert_eq!(
        wrong_tenant.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    let logs_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(10)?);
    let logs_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        logs_scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let wrong_signal = TraceStore::new()
        .scan(
            authority.governor(),
            tenant,
            &logs_ledger.snapshot()?,
            TraceScan::all(ScanLimit::new(1)?),
        )
        .expect_err("cross-signal trace scan must fail closed");
    assert_eq!(
        wrong_signal.code(),
        TraceStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}
