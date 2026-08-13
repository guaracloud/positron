use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, Catalog, CatalogSecret, InstanceId, LedgerFailureCode,
    MountQualification, PreparedStoreBlock, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};

use super::support::{TemporaryRoot, establish_kernel_authority};

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
    assert_eq!(retry.position(), first.position());
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
    let retry = ledger.append(prepared(3, b"retry-safe".to_vec())?)?;
    assert_eq!(retry.position(), original.position());
    assert_eq!(retry.segment_id(), original.segment_id());
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let after_restart = reopened.append(prepared(3, b"retry-safe".to_vec())?)?;
    assert_eq!(after_restart.position(), original.position());
    assert_eq!(reopened.snapshot()?.blocks().len(), 1);
    Ok(())
}

#[test]
fn snapshots_hold_governed_capacity_until_drop_and_repeated_snapshots_are_bounded()
-> Result<(), Box<dyn Error>> {
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
    ledger.append(prepared(8, b"snapshot-capacity".to_vec())?)?;
    let baseline = authority.governor().inspect()?.outstanding_total();
    let first = ledger.snapshot()?;
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline + 1
    );

    let mut snapshots = vec![first];
    let failure = loop {
        match ledger.snapshot() {
            Ok(snapshot) => snapshots.push(snapshot),
            Err(failure) => break failure,
        }
    };
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    drop(snapshots);
    assert_eq!(
        authority.governor().inspect()?.outstanding_total(),
        baseline
    );
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    Ok(())
}

#[test]
fn shutdown_refuses_new_ingest_before_protected_completion_or_storage_mutation()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(
            TenantId::from_bytes([0x41; 16])?,
            SignalKind::Logs,
            VirtualShardId::new(9)?,
        ),
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let active = root.path().join("segments/active");
    let before = directory_file_bytes(&active)?;
    let recovery_before = authority.governor().inspect()?.outstanding_recovery();
    authority.begin_shutdown()?;

    let failure = ledger
        .append(prepared(9, b"refused-after-shutdown".to_vec())?)
        .expect_err("shutdown refuses new ordinary ingest");
    assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
    assert_eq!(directory_file_bytes(&active)?, before);
    assert_eq!(
        authority.governor().inspect()?.outstanding_recovery(),
        recovery_before
    );
    Ok(())
}

fn directory_file_bytes(path: &std::path::Path) -> Result<u64, Box<dyn Error>> {
    let mut bytes = 0_u64;
    for entry in std::fs::read_dir(path)? {
        let metadata = entry?.metadata()?;
        if metadata.is_file() {
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or("fixture byte count overflow")?;
        }
    }
    Ok(bytes)
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
    ledger.append(prepared(4, first.clone())?)?;
    let failure = ledger
        .append(prepared(5, vec![0x62; 600_000])?)
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
    let predecessor = first.append(prepared(6, b"pre-crash".to_vec())?)?;
    drop(first);

    let recovered = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let successor = recovered.append(prepared(7, b"post-crash".to_vec())?)?;

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
    let committed = ledger.append(prepared(8, b"sealed-block".to_vec())?)?;

    let sealed = ledger.seal()?;
    assert_eq!(sealed.segment_id(), committed.segment_id());
    assert_eq!(sealed.frontier(), committed.position());

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    assert_eq!(reopened.snapshot()?.frontier(), committed.position());
    assert_eq!(reopened.snapshot()?.blocks()[0].payload(), b"sealed-block");
    Ok(())
}
