use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, CommittedLedgerReader, InstanceId,
    LedgerFailureCode, MountQualification, PreparedStoreBlock, PrimaryDataVolume,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};

use super::support::{TemporaryRoot, establish_kernel_authority};

fn prepared(
    scope: SegmentScope,
    marker: u8,
    payload: &[u8],
) -> Result<PreparedStoreBlock<'static>, positron_kernel::LedgerFailure> {
    PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([marker; 16])?,
        payload.to_vec(),
    )
}

#[test]
fn committed_reader_coexists_with_writer_and_observes_acknowledged_appends()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x74; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let reader = CommittedLedgerReader::open(&authority, &catalog, scope, key())?;
    assert_eq!(ledger.scope(), scope);
    assert_eq!(
        format!("{reader:?}"),
        "CommittedLedgerReader { <storage-and-key-redacted> }"
    );
    assert_eq!(reader.snapshot()?.blocks().len(), 0);
    ledger.append(prepared(scope, 1, b"first")?)?;
    let first = reader.snapshot()?;
    assert_eq!(first.frontier().value(), 1);
    assert_eq!(first.blocks().len(), 1);
    ledger.append(prepared(scope, 2, b"second")?)?;
    let second = reader.snapshot()?;
    assert_eq!(second.frontier().value(), 2);
    assert_eq!(second.blocks().len(), 2);

    drop(ledger);
    let active_directory = root.path().join("segments/active");
    let segment = fs::read_dir(&active_directory)?
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".segment"))
        .ok_or("active segment missing")?
        .path();
    let frontier = fs::read_dir(&active_directory)?
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".frontier"))
        .ok_or("active frontier missing")?
        .path();
    let mut file = OpenOptions::new().append(true).open(&segment)?;
    file.write_all(b"unacknowledged-tail")?;
    file.sync_all()?;
    assert_eq!(reader.snapshot()?.blocks().len(), 2);

    fs::remove_file(frontier)?;
    assert!(reader.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn observed_snapshot_rejects_a_malformed_active_frontier_without_repair_or_drift()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x75; 16])?,
        CatalogSecret::from_owned(Box::new([0x76; 32]), Box::new([0x77; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x78; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let receipt = ledger.append(prepared(scope, 1, b"frontier")?)?;
    let reader = CommittedLedgerReader::open(&authority, &catalog, scope, key())?;
    let frontier_path = root
        .path()
        .join("segments/active")
        .join(format!("{}.frontier", hex(receipt.segment_id().to_bytes())));
    let segment_path = root
        .path()
        .join("segments/active")
        .join(format!("{}.segment", hex(receipt.segment_id().to_bytes())));
    let frontier_before = fs::read(&frontier_path)?;
    let segment_before = fs::read(&segment_path)?;
    let resources_before = authority.governor().inspect()?;
    let catalog_before = {
        let snapshot = catalog.pin()?;
        (snapshot.identity(), snapshot.number())
    };

    let mut frontier = OpenOptions::new().append(true).open(&frontier_path)?;
    frontier.write_all(&[0])?;
    frontier.sync_all()?;
    let malformed_frontier = fs::read(&frontier_path)?;

    let failure = match reader.snapshot() {
        Ok(_) => return Err("a malformed active frontier unexpectedly reconstructed".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
    assert_eq!(fs::read(&frontier_path)?, malformed_frontier);
    assert_eq!(fs::read(&segment_path)?, segment_before);
    assert_eq!(authority.governor().inspect()?, resources_before);
    let catalog_after = {
        let snapshot = catalog.pin()?;
        (snapshot.identity(), snapshot.number())
    };
    assert_eq!(catalog_after, catalog_before);
    assert_eq!(frontier_before.len() + 1, malformed_frontier.len());
    Ok(())
}

fn hex(bytes: [u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
