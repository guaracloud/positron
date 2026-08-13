use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, Catalog, CatalogSecret, InstanceId, LedgerFailureCode,
    MountQualification, PreparedStoreBlock, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};

use super::support::{TemporaryRoot, establish_kernel_authority};

mod capacity_and_lifecycle;

fn prepared(
    marker: u8,
    payload: Vec<u8>,
) -> Result<PreparedStoreBlock, positron_kernel::LedgerFailure> {
    PreparedStoreBlock::new(StoreBlockIdentity::new([marker; 16])?, payload)
}

#[test]
fn acknowledged_block_is_visible_and_survives_reopen() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x11; 16])?,
        CatalogSecret::from_owned(Box::new([0x21; 32]), Box::new([0x31; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );

    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    let receipt = ledger.append(prepared(1, b"canonical-log-block".to_vec())?)?;

    assert_eq!(receipt.position().value(), 1);
    let snapshot = ledger.snapshot()?;
    assert_eq!(snapshot.frontier(), receipt.position());
    assert_eq!(snapshot.blocks().len(), 1);
    assert_eq!(snapshot.blocks()[0].position(), receipt.position());
    assert_eq!(snapshot.blocks()[0].payload(), b"canonical-log-block");
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x51; 32])),
    )?;
    let recovered = reopened.snapshot()?;
    assert_eq!(recovered.frontier(), receipt.position());
    assert_eq!(recovered.blocks().len(), 1);
    assert_eq!(recovered.blocks()[0].payload(), b"canonical-log-block");
    Ok(())
}

#[test]
fn block_identity_distinguishes_legitimate_duplicates_from_idempotent_retries()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x12; 16])?,
        CatalogSecret::from_owned(Box::new([0x22; 32]), Box::new([0x32; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(2)?,
    );
    let key = || SegmentProtectionKey::from_owned(Box::new([0x52; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let first_id = StoreBlockIdentity::new([0x61; 16])?;
    let second_id = StoreBlockIdentity::new([0x62; 16])?;
    let first = ledger.append(PreparedStoreBlock::new(first_id, b"same".to_vec())?)?;
    let retry = ledger.append(PreparedStoreBlock::new(first_id, b"same".to_vec())?)?;
    let second = ledger.append(PreparedStoreBlock::new(second_id, b"same".to_vec())?)?;
    assert_eq!(retry, first);
    assert_eq!(second.position().value(), 2);
    let conflict = ledger
        .append(PreparedStoreBlock::new(first_id, b"changed".to_vec())?)
        .expect_err("one block identity cannot name different canonical bytes");
    assert_eq!(conflict.code(), LedgerFailureCode::IdempotencyConflict);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, key())?;
    let retry = reopened.append(PreparedStoreBlock::new(first_id, b"same".to_vec())?)?;
    assert_eq!(retry, first);
    let snapshot = reopened.snapshot()?;
    assert_eq!(snapshot.blocks().len(), 2);
    assert_eq!(snapshot.blocks()[0].identity(), first_id);
    assert_eq!(snapshot.blocks()[1].identity(), second_id);
    assert_eq!(
        snapshot.blocks()[0].payload(),
        snapshot.blocks()[1].payload()
    );
    Ok(())
}

#[test]
fn cancelled_work_is_rejected_before_resource_admission_and_mutation() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x16; 16])?,
        CatalogSecret::from_owned(Box::new([0x26; 32]), Box::new([0x36; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(
            TenantId::from_bytes([0x41; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(6)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x56; 32])),
    )?;
    let cancellation = AppendCancellation::new();
    cancellation.cancel();

    let failure = ledger
        .append_cancellable(prepared(2, b"cancelled".to_vec())?, &cancellation)
        .expect_err("cancelled work cannot enter the durability path");
    assert_eq!(failure.code(), LedgerFailureCode::Cancelled);
    assert_eq!(ledger.snapshot()?.blocks().len(), 0);
    Ok(())
}

#[test]
fn unregistered_physical_tenant_is_refused_before_storage_mutation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x17; 16])?,
        CatalogSecret::from_owned(Box::new([0x27; 32]), Box::new([0x37; 32])),
    )?;
    let failure = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(
            TenantId::from_bytes([0x42; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(7)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )
    .expect_err("ledger recovery must be attributed to a configured physical tenant");
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    assert!(!root.path().join("segments").exists());

    let registered = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(
            TenantId::from_bytes([0x41; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(7)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x57; 32])),
    )?;
    assert!(registered.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn a_second_live_ledger_is_refused_before_it_can_roll_the_active_segment()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x14; 16])?,
        CatalogSecret::from_owned(Box::new([0x24; 32]), Box::new([0x34; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let first = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;

    let failure = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )
    .expect_err("one kernel authority cannot expose a competing live ledger");
    assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
    assert_eq!(first.snapshot()?.blocks().len(), 0);

    let distinct = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(
            TenantId::from_bytes([0x41; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(2)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    assert!(distinct.snapshot()?.blocks().is_empty());
    drop(first);
    let reacquired = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )?;
    assert!(reacquired.snapshot()?.blocks().is_empty());
    Ok(())
}

#[test]
fn retrying_the_same_canonical_block_does_not_admit_a_duplicate() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x15; 16])?,
        CatalogSecret::from_owned(Box::new([0x25; 32]), Box::new([0x35; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x41; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(5)?,
    );
    let wrapping_key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;

    let original = ledger.append(prepared(3, b"retry-safe".to_vec())?)?;
    ledger.append(prepared(4, b"later-block".to_vec())?)?;
    let retry = ledger.append(prepared(3, b"retry-safe".to_vec())?)?;
    assert_eq!(retry, original);
    assert_eq!(ledger.snapshot()?.blocks().len(), 2);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let after_restart = reopened.append(prepared(3, b"retry-safe".to_vec())?)?;
    assert_eq!(after_restart, original);
    assert_eq!(reopened.snapshot()?.blocks().len(), 2);
    Ok(())
}
