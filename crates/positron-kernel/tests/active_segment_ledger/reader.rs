use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, CommittedLedgerReader, InstanceId,
    MountQualification, PreparedStoreBlock, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
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
    assert_eq!(reader.snapshot()?.blocks().len(), 0);
    ledger.append(prepared(scope, 1, b"first")?)?;
    let first = reader.snapshot()?;
    assert_eq!(first.frontier().value(), 1);
    assert_eq!(first.blocks().len(), 1);
    ledger.append(prepared(scope, 2, b"second")?)?;
    let second = reader.snapshot()?;
    assert_eq!(second.frontier().value(), 2);
    assert_eq!(second.blocks().len(), 2);
    Ok(())
}
