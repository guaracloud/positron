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

mod oracle;
mod persisted_corruption;

use oracle::Oracle;
use persisted_corruption::{PersistedArtifact, run_persisted_corruption_case};

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
    let scope = scope();
    let mut ledger = open(&authority, &catalog, scope).expect("fresh ledger opens");
    let mut oracle = Oracle::new();

    for (index, selector) in data.iter().copied().take(24).enumerate() {
        match selector % 13 {
            0 => {
                let (identity, payload) = block_parts(index, selector);
                let receipt = ledger
                    .append(prepared(identity, payload.clone()))
                    .expect("ordinary bounded fuzz append succeeds");
                oracle.record(identity, payload, receipt);
            },
            1 => {
                let event = fault_event(selector);
                let (identity, payload) = block_parts(index, selector);
                let result =
                    with_ledger_fault(event, || ledger.append(prepared(identity, payload.clone())));
                let failure =
                    result.expect_err("an injected filesystem boundary cannot acknowledge");
                assert_eq!(failure.completion_state(), fault_completion(event));
                drop(ledger);
                ledger = open(&authority, &catalog, scope).expect("fault recovery opens");
                if fault_commits(event) {
                    let receipt = ledger
                        .append(prepared(identity, payload.clone()))
                        .expect("ambiguous successor replays exactly");
                    oracle.record(identity, payload, receipt);
                }
            },
            2 => {
                drop(ledger);
                ledger = open(&authority, &catalog, scope).expect("restart recovery opens");
            },
            3 => {
                ledger.seal().expect("bounded seal succeeds");
                oracle.record_seal();
                ledger = open(&authority, &catalog, scope).expect("sealed ledger reopens");
            },
            4 => {
                if let Some((identity, payload, receipt)) = oracle.first() {
                    let retry = prepared(identity, payload.to_vec());
                    let actual = ledger.append(retry).expect("same identity and bytes retry");
                    assert_eq!(actual, receipt);
                }
            },
            5 => {
                if let Some((identity, _, _)) = oracle.first() {
                    let conflict = prepared(identity, vec![selector, 0xff]);
                    assert_eq!(
                        ledger
                            .append(conflict)
                            .expect_err("identity reuse must conflict")
                            .code(),
                        LedgerFailureCode::IdempotencyConflict
                    );
                }
            },
            6 => {
                if let Some((_, existing_payload, _)) = oracle.first() {
                    let identity = identity(index);
                    if !oracle.contains(identity) {
                        let payload = existing_payload.to_vec();
                        let receipt = ledger
                            .append(prepared(identity, payload.clone()))
                            .expect("equal bytes under distinct identity append");
                        oracle.record(identity, payload, receipt);
                    }
                }
            },
            operation => {
                let artifact = PersistedArtifact::from_operation(operation)
                    .expect("the corruption operation is in range");
                assert_eq!(run_persisted_corruption_case(artifact, selector), artifact);
            },
        }
        oracle.assert_ledger(&ledger);
    }

    drop(ledger);
    let recovered = open(&authority, &catalog, scope).expect("final recovery opens");
    oracle.assert_ledger(&recovered);
    assert_eq!(
        recovered.snapshot().expect("final frontier").frontier(),
        oracle.frontier()
    );
}

fn block_parts(index: usize, selector: u8) -> (StoreBlockIdentity, Vec<u8>) {
    (
        identity(index),
        vec![selector, u8::try_from(index).expect("fuzz operation bound")],
    )
}

fn prepared(identity: StoreBlockIdentity, payload: Vec<u8>) -> PreparedStoreBlock {
    PreparedStoreBlock::new(scope(), identity, payload).expect("bounded fuzz block")
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

fn scope() -> SegmentScope {
    SegmentScope::new(
        TenantId::from_bytes([0x43; 16]).expect("fixed tenant identity"),
        SignalKind::Logs,
        VirtualShardId::new(1).expect("fixed shard identity"),
    )
}

fn fault_event(selector: u8) -> LedgerFileEvent {
    const EVENTS: [LedgerFileEvent; 11] = [
        LedgerFileEvent::WriteFrame,
        LedgerFileEvent::PartialFrameWrite,
        LedgerFileEvent::SynchronizeFrame,
        LedgerFileEvent::InspectSegmentMetadata,
        LedgerFileEvent::RemoveFrontierTemporary,
        LedgerFileEvent::CreateFrontierTemporary,
        LedgerFileEvent::WriteFrontier,
        LedgerFileEvent::PartialFrontierWrite,
        LedgerFileEvent::SynchronizeFrontier,
        LedgerFileEvent::RenameFrontier,
        LedgerFileEvent::SynchronizeFrontierDirectory,
    ];
    EVENTS[usize::from(selector) % EVENTS.len()]
}

fn fault_commits(event: LedgerFileEvent) -> bool {
    event == LedgerFileEvent::SynchronizeFrontierDirectory
}

fn fault_completion(event: LedgerFileEvent) -> super::LedgerCompletionState {
    use super::LedgerCompletionState;
    match event {
        LedgerFileEvent::WriteFrame => LedgerCompletionState::RejectedBeforeMutation,
        LedgerFileEvent::SynchronizeFrontierDirectory => LedgerCompletionState::CommitAmbiguous,
        _ => LedgerCompletionState::RecoveryRequired,
    }
}
