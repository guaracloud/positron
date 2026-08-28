use std::error::Error;
use std::fs;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::support::{TemporaryRoot, establish_authority};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, LedgerFailureCode, MountQualification,
    OrdinaryPool, PreparedStoreBlock, PrimaryDataVolume, ResourceAmounts, ResourceDimension,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};

#[test]
fn observed_reader_does_not_recreate_an_absent_segments_directory() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x84; 32])),
    )?;
    let segments = root.path().join("segments");
    assert!(segments.is_dir());
    fs::remove_dir_all(&segments)?;

    let failure = ledger
        .reader()
        .expect_err("observed reader must not create missing storage");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert!(
        !segments.exists(),
        "reader opening mutated the storage root"
    );
    Ok(())
}

#[test]
fn observed_reader_admits_reconstruction_before_reading_segment_bytes() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x85; 16])?,
        CatalogSecret::from_owned(Box::new([0x86; 32]), Box::new([0x87; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x88; 32])),
    )?;
    ledger.append(PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([0x89; 16])?,
        b"reader-admission".to_vec(),
    )?)?;
    for entry in fs::read_dir(root.path().join("segments/active"))? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "segment")
        {
            fs::remove_file(path)?;
        }
    }

    let before = authority.governor().inspect()?;
    let dimension = ResourceDimension::MemoryBytes;
    let shared = before
        .pool_capacity(OrdinaryPool::Shared, dimension)
        .checked_sub(before.pool_usage(OrdinaryPool::Shared, dimension))
        .ok_or("shared memory usage exceeds capacity")?;
    let query = before
        .pool_capacity(OrdinaryPool::InteractiveQueryTail, dimension)
        .checked_sub(before.pool_usage(OrdinaryPool::InteractiveQueryTail, dimension))
        .ok_or("query memory usage exceeds capacity")?;
    let blocker_amount = shared
        .checked_add(query)
        .and_then(|available| available.checked_sub(1))
        .ok_or("admission blocker cannot leave one byte of headroom")?;
    let blocker = authority.governor().reserve(WorkClaim::tenant(
        scope.tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(dimension, blocker_amount)?,
    )?)?;

    let reader = ledger.reader()?;
    let failure = match reader.snapshot() {
        Ok(_) => return Err("reader reconstructed despite saturated capacity".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    drop(blocker);
    Ok(())
}
