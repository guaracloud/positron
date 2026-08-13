use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, Catalog, CatalogSecret, InstanceId, LedgerFailureCode,
    MountQualification, PreparedStoreBlock, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
};

use super::support::{TemporaryRoot, establish_kernel_authority};

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
    let receipt = ledger.append(PreparedStoreBlock::new(b"canonical-log-block".to_vec())?)?;

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
        .append_cancellable(
            PreparedStoreBlock::new(b"cancelled".to_vec())?,
            &cancellation,
        )
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

    let original = ledger.append(PreparedStoreBlock::new(b"retry-safe".to_vec())?)?;
    let retry = ledger.append(PreparedStoreBlock::new(b"retry-safe".to_vec())?)?;
    assert_eq!(retry.position(), original.position());
    assert_eq!(retry.segment_id(), original.segment_id());
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let after_restart = reopened.append(PreparedStoreBlock::new(b"retry-safe".to_vec())?)?;
    assert_eq!(after_restart.position(), original.position());
    assert_eq!(reopened.snapshot()?.blocks().len(), 1);
    Ok(())
}

#[test]
fn retained_ledger_memory_is_bounded_before_append_mutation() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(
            TenantId::from_bytes([0x41; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(8)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let first = vec![0x61; 600_000];
    ledger.append(PreparedStoreBlock::new(first.clone())?)?;
    let failure = ledger
        .append(PreparedStoreBlock::new(vec![0x62; 600_000])?)
        .expect_err("retained plaintext cannot exceed the governed ledger bound");
    assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    assert_eq!(ledger.snapshot()?.blocks()[0].payload(), first);
    Ok(())
}

#[test]
fn recovery_seals_the_predecessor_before_appending_under_a_fresh_segment_dek()
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
        VirtualShardId::new(1)?,
    );
    let wrapping_key = || SegmentProtectionKey::from_owned(Box::new([0x52; 32]));

    let first = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let predecessor = first.append(PreparedStoreBlock::new(b"pre-crash".to_vec())?)?;
    drop(first);

    let recovered = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let successor = recovered.append(PreparedStoreBlock::new(b"post-crash".to_vec())?)?;

    assert_ne!(successor.segment_id(), predecessor.segment_id());
    let snapshot = recovered.snapshot()?;
    assert_eq!(snapshot.blocks().len(), 2);
    assert_eq!(snapshot.blocks()[0].payload(), b"pre-crash");
    assert_eq!(snapshot.blocks()[1].payload(), b"post-crash");
    drop(recovered);

    let verified_again = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    assert_eq!(verified_again.snapshot()?.blocks().len(), 2);
    Ok(())
}

#[test]
fn explicit_seal_publishes_the_same_bytes_as_an_immutable_segment() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
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
    let wrapping_key = || SegmentProtectionKey::from_owned(Box::new([0x53; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let committed = ledger.append(PreparedStoreBlock::new(b"sealed-block".to_vec())?)?;

    let sealed = ledger.seal()?;
    assert_eq!(sealed.segment_id(), committed.segment_id());
    assert_eq!(sealed.frontier(), committed.position());

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    assert_eq!(reopened.snapshot()?.frontier(), committed.position());
    assert_eq!(reopened.snapshot()?.blocks()[0].payload(), b"sealed-block");
    Ok(())
}
