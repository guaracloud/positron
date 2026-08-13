use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::catalog::fuzz_authority;
use crate::{Catalog, CatalogSecret, InstanceId, MountQualification, PrimaryDataVolume};

use super::fault::{LedgerFileEvent, with_ledger_fault};
use super::{ActiveSegmentLedger, PreparedStoreBlock, SegmentProtectionKey, SegmentScope};

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
        match selector % 4 {
            0 => {
                let payload = vec![selector, u8::try_from(index).unwrap_or(u8::MAX)];
                let _ = ledger
                    .append(PreparedStoreBlock::new(payload).expect("bounded nonempty fuzz block"));
            },
            1 => {
                let payload = vec![selector, u8::try_from(index).unwrap_or(u8::MAX)];
                let result = with_ledger_fault(fault_event(selector), || {
                    ledger.append(
                        PreparedStoreBlock::new(payload).expect("bounded nonempty fuzz block"),
                    )
                });
                if result.is_err() {
                    drop(ledger);
                    ledger = open(&authority, &catalog, scope).expect("fault recovery opens");
                }
            },
            2 => {
                drop(ledger);
                ledger = open(&authority, &catalog, scope).expect("restart recovery opens");
            },
            _ => {
                let _ = ledger.seal();
                ledger = open(&authority, &catalog, scope).expect("sealed ledger reopens");
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
    assert_eq!(snapshot.frontier().value(), snapshot.blocks().len() as u64);
    for (index, block) in snapshot.blocks().iter().enumerate() {
        assert_eq!(block.position().value(), index as u64 + 1);
        assert!(!block.payload().is_empty());
    }
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
