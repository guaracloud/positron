use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::catalog::fuzz_authority;
use crate::{Catalog, CatalogSecret, InstanceId, MountQualification, PrimaryDataVolume};

use super::fault::{LedgerFileEvent, with_ledger_fault};
use super::{
    ActiveSegmentLedger, LedgerFailureCode, PreparedStoreBlock, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-active-segment-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).ok()?;
        Some(Self(path))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove active-segment fuzz root: {error}");
        }
    }
}

pub(super) fn fuzz_active_segment_stateful(data: &[u8]) {
    if data.len() > 128 {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    let Some(volume) = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost).ok()
    else {
        return;
    };
    let Some(authority) = fuzz_authority(volume) else {
        return;
    };
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16]).expect("fixed instance identity"),
        catalog_secret(),
    )
    .expect("fuzz catalog opens");
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x43; 16]).expect("fixed tenant identity"),
        SignalKind::Logs,
        VirtualShardId::new(1).expect("fixed shard identity"),
    );
    let mut ledger = open(&authority, &catalog, scope).expect("fresh ledger opens");

    for (index, selector) in data.iter().copied().take(24).enumerate() {
        match selector % 7 {
            0 => {
                ledger
                    .append(block(index, selector))
                    .expect("ordinary bounded fuzz append succeeds");
            },
            1 => {
                let result = with_ledger_fault(fault_event(selector), || {
                    ledger.append(block(index, selector))
                });
                result.expect_err("an injected filesystem boundary cannot acknowledge");
                drop(ledger);
                ledger = open(&authority, &catalog, scope).expect("fault recovery opens");
            },
            2 => {
                drop(ledger);
                ledger = open(&authority, &catalog, scope).expect("restart recovery opens");
            },
            3 => {
                ledger.seal().expect("bounded seal succeeds");
                ledger = open(&authority, &catalog, scope).expect("sealed ledger reopens");
            },
            4 => {
                let snapshot = ledger.snapshot().expect("snapshot for retry");
                if let Some(existing) = snapshot.blocks().first() {
                    let retry =
                        PreparedStoreBlock::new(existing.identity(), existing.payload().to_vec())
                            .expect("existing block remains bounded");
                    let receipt = ledger.append(retry).expect("same identity and bytes retry");
                    assert_eq!(receipt.position(), existing.position());
                }
            },
            5 => {
                let snapshot = ledger.snapshot().expect("snapshot for conflict");
                if let Some(existing) = snapshot.blocks().first() {
                    let conflict =
                        PreparedStoreBlock::new(existing.identity(), vec![selector, 0xff])
                            .expect("bounded conflict");
                    assert_eq!(
                        ledger
                            .append(conflict)
                            .expect_err("identity reuse must conflict")
                            .code(),
                        LedgerFailureCode::IdempotencyConflict
                    );
                }
            },
            _ => {
                let snapshot = ledger.snapshot().expect("snapshot for duplicate bytes");
                if let Some(existing) = snapshot.blocks().first() {
                    let identity = identity(index);
                    if identity != existing.identity()
                        && snapshot
                            .blocks()
                            .iter()
                            .all(|block| block.identity() != identity)
                    {
                        ledger
                            .append(
                                PreparedStoreBlock::new(identity, existing.payload().to_vec())
                                    .expect("bounded distinct identity"),
                            )
                            .expect("equal bytes under distinct identity append");
                    }
                }
            },
        }
        assert_snapshot_invariants(&ledger);
    }

    drop(ledger);
    let recovered = open(&authority, &catalog, scope).expect("final recovery opens");
    assert_snapshot_invariants(&recovered);
}

fn assert_snapshot_invariants(ledger: &ActiveSegmentLedger<'_, '_>) {
    let snapshot = ledger.snapshot().expect("fuzz snapshot is available");
    assert_eq!(
        snapshot.frontier().value(),
        u64::try_from(snapshot.blocks().len()).expect("bounded snapshot length")
    );
    for (index, block) in snapshot.blocks().iter().enumerate() {
        assert_eq!(
            block.position().value(),
            u64::try_from(index).expect("bounded block index") + 1
        );
        assert!(!block.payload().is_empty());
        assert_eq!(
            snapshot
                .blocks()
                .iter()
                .filter(|candidate| candidate.identity() == block.identity())
                .count(),
            1
        );
    }
}

fn block(index: usize, selector: u8) -> PreparedStoreBlock {
    PreparedStoreBlock::new(
        identity(index),
        vec![selector, u8::try_from(index).expect("fuzz operation bound")],
    )
    .expect("bounded fuzz block")
}

fn identity(index: usize) -> StoreBlockIdentity {
    StoreBlockIdentity::new([u8::try_from(index + 1).expect("fuzz operation identity bound"); 16])
        .expect("nonzero fuzz identity")
}

fn open<'authority, 'catalog>(
    authority: &'authority crate::StorageKernelResourceAuthority,
    catalog: &'catalog Catalog<'authority>,
    scope: SegmentScope,
) -> Result<ActiveSegmentLedger<'authority, 'catalog>, super::LedgerFailure> {
    ActiveSegmentLedger::open(
        authority,
        catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x91; 32])),
    )
}

fn catalog_secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32]))
}

fn fault_event(selector: u8) -> LedgerFileEvent {
    const EVENTS: [LedgerFileEvent; 8] = [
        LedgerFileEvent::WriteFrame,
        LedgerFileEvent::PartialFrameWrite,
        LedgerFileEvent::SynchronizeFrame,
        LedgerFileEvent::WriteFrontier,
        LedgerFileEvent::PartialFrontierWrite,
        LedgerFileEvent::SynchronizeFrontier,
        LedgerFileEvent::RenameFrontier,
        LedgerFileEvent::SynchronizeFrontierDirectory,
    ];
    EVENTS[usize::from(selector) % EVENTS.len()]
}
