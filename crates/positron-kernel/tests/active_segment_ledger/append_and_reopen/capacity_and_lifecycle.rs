use super::*;

fn ledger_fixture() -> Result<
    (
        TemporaryRoot,
        positron_kernel::StorageKernelResourceAuthority,
    ),
    Box<dyn Error>,
> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    Ok((root, authority))
}

#[test]
fn snapshots_hold_governed_capacity_until_drop_and_repeated_snapshots_are_bounded()
-> Result<(), Box<dyn Error>> {
    let (root, authority) = ledger_fixture()?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(8)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let committed = ledger.append(prepared(scope, 8, b"snapshot-capacity".to_vec())?)?;
    let baseline = authority.governor().inspect()?.outstanding_total();
    let active = root.path().join("segments/active");
    let before = directory_file_bytes(&active)?;
    let mut snapshots = vec![ledger.snapshot()?];
    let failure = loop {
        match ledger.snapshot() {
            Ok(snapshot) => snapshots.push(snapshot),
            Err(failure) => break failure,
        }
    };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    assert_eq!(
        ledger.append(prepared(scope, 8, b"snapshot-capacity".to_vec())?)?,
        committed
    );
    assert_eq!(
        ledger
            .append(prepared(scope, 8, b"snapshot-conflict".to_vec())?)
            .expect_err("conflict is resolved before new-work admission")
            .code(),
        LedgerFailureCode::IdempotencyConflict
    );
    assert_eq!(
        ledger
            .append(prepared(scope, 9, b"new-work".to_vec())?)
            .expect_err("new work remains capacity governed")
            .code(),
        LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(directory_file_bytes(&active)?, before);
    drop(snapshots);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline
    );
    drop(root);
    Ok(())
}

#[test]
fn shutdown_refuses_new_ingest_before_protected_completion_or_storage_mutation()
-> Result<(), Box<dyn Error>> {
    let (root, authority) = ledger_fixture()?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(9)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let committed = ledger.append(prepared(scope, 9, b"committed-before-shutdown".to_vec())?)?;
    let active = root.path().join("segments/active");
    let before = directory_file_bytes(&active)?;
    let usage = authority.governor().inspect()?.outstanding_total();
    authority.begin_shutdown()?;
    assert_eq!(
        ledger.append(prepared(scope, 9, b"committed-before-shutdown".to_vec())?)?,
        committed
    );
    assert_eq!(
        ledger
            .append(prepared(scope, 9, b"changed".to_vec())?)
            .expect_err("conflict")
            .code(),
        LedgerFailureCode::IdempotencyConflict
    );
    assert_eq!(
        ledger
            .append(prepared(scope, 10, b"new".to_vec())?)
            .expect_err("new work refused")
            .code(),
        LedgerFailureCode::ResourceAdmissionRefused
    );
    assert_eq!(directory_file_bytes(&active)?, before);
    assert_eq!(authority.governor().inspect()?.outstanding_total(), usage);
    Ok(())
}

fn directory_file_bytes(path: &std::path::Path) -> Result<u64, Box<dyn Error>> {
    std::fs::read_dir(path)?.try_fold(0_u64, |total, entry| {
        Ok(total
            .checked_add(entry?.metadata()?.len())
            .ok_or("fixture byte count overflow")?)
    })
}

#[test]
fn retained_ledger_memory_is_bounded_before_append_mutation() -> Result<(), Box<dyn Error>> {
    let (_root, authority) = ledger_fixture()?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(8)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    ledger.append(prepared(scope, 4, vec![0x61; 600_000])?)?;
    assert_eq!(
        ledger
            .append(prepared(scope, 5, vec![0x62; 600_000])?)
            .expect_err("bounded")
            .code(),
        LedgerFailureCode::LimitExceeded
    );
    Ok(())
}

#[test]
fn recovery_seals_the_predecessor_before_appending_under_a_fresh_segment_dek()
-> Result<(), Box<dyn Error>> {
    let (_root, authority) = ledger_fixture()?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x12; 16])?,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x32; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x52; 32]));
    let first = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let predecessor = first.append(prepared(scope, 6, b"pre-crash".to_vec())?)?;
    drop(first);
    let recovered = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    assert_ne!(
        recovered
            .append(prepared(scope, 7, b"post-crash".to_vec())?)?
            .segment_id(),
        predecessor.segment_id()
    );
    Ok(())
}

#[test]
fn explicit_seal_publishes_the_same_bytes_as_an_immutable_segment() -> Result<(), Box<dyn Error>> {
    let (_root, authority) = ledger_fixture()?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x13; 16])?,
        CatalogSecret::from_owned(Box::new([0x23; 32]), Box::new([0x33; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x53; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let committed = ledger.append(prepared(scope, 8, b"sealed-block".to_vec())?)?;
    assert_eq!(ledger.seal()?.segment_id(), committed.segment_id());
    assert_eq!(
        ActiveSegmentLedger::open(&authority, &catalog, scope, key())?.append(prepared(
            scope,
            8,
            b"sealed-block".to_vec()
        )?)?,
        committed
    );
    Ok(())
}
