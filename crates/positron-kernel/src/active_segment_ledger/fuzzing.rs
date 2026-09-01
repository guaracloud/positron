use std::fs;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use crate::catalog::fuzz_authority;
use crate::{
    Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch, InstanceId,
    MountQualification, PrimaryDataVolume, ResourceAmounts, ResourceDimension,
    RetentionTimeAuthority, StorageKernelResourceAuthority, TransactionId, WorkClaim, WorkKind,
};

use super::fault::{LedgerFileEvent, with_ledger_fault};
use super::{
    ActiveSegmentLedger, LedgerFailureCode, LedgerSnapshot, PreparedStoreBlock,
    SegmentProtectionKey, SegmentScope, SnapshotLeaseId, SnapshotLeaseUsage, StoreBlockIdentity,
};

mod oracle;
mod persisted_corruption;

use oracle::{Oracle, SnapshotExpectation};
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
    let instance = InstanceId::new([0x81; 16]).expect("fixed instance identity");
    let catalog =
        Catalog::open(&authority, instance, catalog_secret()).expect("fuzz catalog opens");
    let scope = scope();
    install_retention_policy(&catalog, instance, scope.tenant_id());
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        positron_domain::time::UnixNanoseconds::new(1_000_000_000),
    );
    let mut ledger =
        open(&authority, &retention_time, &catalog, scope).expect("fresh ledger opens");
    let mut oracle = Oracle::new();
    let mut lease: Option<(SnapshotLeaseId, u64, SnapshotExpectation)> = None;
    let mut protected_snapshot: Option<(LedgerSnapshot<'_>, SnapshotExpectation)> = None;

    for (index, selector) in data.iter().copied().take(24).enumerate() {
        let operation = selector % 25;
        match operation {
            0 => {
                let (identity, payload) = block_parts(index, selector);
                let receipt = ledger
                    .append(prepared_retained(
                        &ledger,
                        &authority,
                        identity,
                        payload.clone(),
                    ))
                    .expect("ordinary bounded fuzz append succeeds");
                oracle.record(identity, payload, receipt, elapsed.nanoseconds());
            },
            1 => {
                let event = fault_event(selector);
                let (identity, payload) = block_parts(index, selector);
                let retained = prepared_retained(&ledger, &authority, identity, payload.clone());
                let result = with_ledger_fault(event, || ledger.append(retained));
                let failure =
                    result.expect_err("an injected filesystem boundary cannot acknowledge");
                assert_eq!(failure.completion_state(), fault_completion(event));
                drop(ledger);
                let Some(recovered) = recover_or_stop(&authority, &retention_time, &catalog, scope)
                else {
                    return;
                };
                ledger = recovered;
                if fault_commits(event) {
                    let receipt = ledger
                        .append(prepared_retained(
                            &ledger,
                            &authority,
                            identity,
                            payload.clone(),
                        ))
                        .expect("ambiguous successor replays exactly");
                    oracle.record(identity, payload, receipt, elapsed.nanoseconds());
                }
            },
            2 => {
                drop(ledger);
                let Some(recovered) = recover_or_stop(&authority, &retention_time, &catalog, scope)
                else {
                    return;
                };
                ledger = recovered;
            },
            3 => {
                ledger.seal().expect("bounded seal succeeds");
                oracle.record_seal();
                let Some(recovered) = recover_or_stop(&authority, &retention_time, &catalog, scope)
                else {
                    return;
                };
                ledger = recovered;
            },
            4 => {
                if let Some((identity, payload, receipt)) = oracle.first() {
                    let retry = prepared_retained(&ledger, &authority, identity, payload.to_vec());
                    let actual = ledger.append(retry).expect("same identity and bytes retry");
                    assert_eq!(actual, receipt);
                }
            },
            5 => {
                if let Some((identity, _, _)) = oracle.first() {
                    let conflict =
                        prepared_retained(&ledger, &authority, identity, vec![selector, 0xff]);
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
                            .append(prepared_retained(
                                &ledger,
                                &authority,
                                identity,
                                payload.clone(),
                            ))
                            .expect("equal bytes under distinct identity append");
                        oracle.record(identity, payload, receipt, elapsed.nanoseconds());
                    }
                }
            },
            7..=12 | 23..=24 => {
                let artifact = PersistedArtifact::from_operation(operation)
                    .expect("the corruption operation is in range");
                assert_eq!(run_persisted_corruption_case(artifact, selector), artifact);
            },
            13 => {
                if lease.is_none() {
                    if let Ok(grant) = ledger.create_snapshot_lease_for(
                        fuzz_now(),
                        NonZeroU64::new(30).expect("positive fuzz lease duration"),
                    ) {
                        lease = Some((
                            grant.identity(),
                            grant.expiry(),
                            Oracle::capture(grant.snapshot()),
                        ));
                    }
                }
            },
            14 => {
                if let Some((identity, _, expected)) = &lease
                    && let Ok(resumed) = ledger.resume_snapshot_lease_with_marker(
                        *identity,
                        fuzz_now(),
                        1,
                        [0x51; 32],
                    )
                {
                    expected.assert_snapshot(resumed.snapshot());
                }
            },
            15 => {
                if let Some((identity, _, expected)) = &lease
                    && let Ok(resumed) = ledger.resume_snapshot_lease(*identity, fuzz_now())
                {
                    expected.assert_snapshot(resumed.snapshot());
                }
            },
            16 => {
                if let Some((identity, _, _)) = lease.take() {
                    let _ = ledger.release_snapshot_lease(identity);
                }
            },
            17 => {
                if let Some((identity, expiry, _)) = lease.take() {
                    let current = 1_u64
                        .checked_add(elapsed.nanoseconds() / 1_000_000_000)
                        .expect("bounded fuzz lease observation");
                    if let Some(delta) = expiry.checked_sub(current) {
                        elapsed
                            .advance(
                                delta
                                    .checked_mul(1_000_000_000)
                                    .expect("bounded fuzz lease movement"),
                            )
                            .expect("bounded fuzz lease expiry movement");
                    }
                    assert_eq!(
                        ledger
                            .resume_snapshot_lease(identity, expiry)
                            .expect_err("lease expiry is exclusive")
                            .code(),
                        LedgerFailureCode::SnapshotExpired
                    );
                }
            },
            18 => {
                if let Some((identity, _, _)) = &lease {
                    let _ = ledger.record_snapshot_lease_usage(
                        *identity,
                        SnapshotLeaseUsage::new(1, 1, 1, 1, 1, 1, 1),
                    );
                }
            },
            19 => {
                let snapshot = ledger.snapshot().expect("protected fuzz snapshot");
                let expected = Oracle::capture(&snapshot);
                protected_snapshot = Some((snapshot, expected));
            },
            20 => {
                protected_snapshot = None;
            },
            21 => {
                let active = ledger.active_segment_id().expect("active segment identity");
                let duration = NonZeroU64::new(1).expect("positive fuzz duration");
                let advances = (selector / 23) % 2 == 1;
                if advances {
                    elapsed
                        .advance(2_000_000_000)
                        .expect("bounded fuzz retention movement");
                }
                let retired = oracle.expired_segments(
                    active,
                    elapsed.nanoseconds(),
                    duration.get() * 1_000_000_000,
                );
                let mut protected = std::collections::BTreeSet::new();
                if let Some((_, expected)) = &protected_snapshot {
                    protected.extend(expected.segments());
                }
                if let Some((_, _, expected)) = &lease {
                    protected.extend(expected.segments());
                }
                let outcome = ledger
                    .begin_retention()
                    .expect("bounded fuzz retention evaluation")
                    .commit()
                    .expect("bounded fuzz retention");
                assert!(outcome.logically_retired_segments() >= retired.len());
                oracle.note_retention(
                    &retired,
                    &protected,
                    outcome.physically_reclaimed_segments(),
                );
                oracle.retire_segments(&retired);
            },
            22 => {
                drop(ledger);
                let Some(recovered) = recover_or_stop(&authority, &retention_time, &catalog, scope)
                else {
                    return;
                };
                ledger = recovered;
                if let Some((identity, _, expected)) = &lease
                    && let Ok(resumed) = ledger.resume_snapshot_lease(*identity, fuzz_now())
                {
                    expected.assert_snapshot(resumed.snapshot());
                }
            },
            _ => {},
        }
        if let Some((snapshot, expected)) = &protected_snapshot {
            expected.assert_snapshot(snapshot);
        }
        oracle.assert_ledger(&ledger, &authority);
    }

    drop(ledger);
    let Some(recovered) = recover_or_stop(&authority, &retention_time, &catalog, scope) else {
        return;
    };
    oracle.assert_ledger(&recovered, &authority);
    assert_eq!(
        recovered.snapshot().expect("final frontier").frontier(),
        oracle.frontier()
    );
}

pub(super) fn fuzz_retention_prepared_block(
    data: &[u8],
    exercise: impl FnOnce(&ActiveSegmentLedger<'_, '_>, TenantId),
) {
    if data.is_empty() || data.len() > 1_048_576 {
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
    let instance = InstanceId::new([0x85; 16]).expect("fixed retention fuzz instance");
    let catalog = Catalog::open(&authority, instance, catalog_secret())
        .expect("retention fuzz catalog opens");
    let scope = scope();
    install_retention_policy(&catalog, instance, scope.tenant_id());
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        positron_domain::time::UnixNanoseconds::new(1_000_000_000),
    );
    let sealed =
        open(&authority, &retention_time, &catalog, scope).expect("retention fuzz ledger opens");
    let capacity = authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                scope.tenant_id(),
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)
                    .expect("bounded retention fuzz capacity"),
            )
            .expect("retention fuzz claim"),
        )
        .expect("retention fuzz reservation");
    let block = sealed
        .begin_store_block(
            capacity,
            StoreBlockIdentity::new([0x86; 16]).expect("retention fuzz block identity"),
        )
        .expect("retention fuzz preparation")
        .finish(data.to_vec())
        .expect("bounded retention fuzz block");
    sealed.append(block).expect("retention fuzz append");
    sealed.seal().expect("retention fuzz seal");
    elapsed
        .advance(2_000_000_000)
        .expect("bounded retention fuzz elapsed time");
    let active = open(&authority, &retention_time, &catalog, scope)
        .expect("retention fuzz active ledger opens");
    exercise(&active, scope.tenant_id());
}

fn fuzz_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1_000, |duration| duration.as_secs())
}

fn block_parts(index: usize, selector: u8) -> (StoreBlockIdentity, Vec<u8>) {
    (
        identity(index),
        vec![selector, u8::try_from(index).expect("fuzz operation bound")],
    )
}

fn prepared(identity: StoreBlockIdentity, payload: Vec<u8>) -> PreparedStoreBlock<'static> {
    PreparedStoreBlock::new(scope(), identity, payload).expect("bounded non-retention fuzz block")
}

fn prepared_retained<'capacity>(
    ledger: &ActiveSegmentLedger<'_, '_>,
    authority: &'capacity StorageKernelResourceAuthority,
    identity: StoreBlockIdentity,
    payload: Vec<u8>,
) -> PreparedStoreBlock<'capacity> {
    let capacity = authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                scope().tenant_id(),
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)
                    .expect("bounded fuzz capacity"),
            )
            .expect("bounded fuzz claim"),
        )
        .expect("bounded fuzz reservation");
    ledger
        .begin_store_block(capacity, identity)
        .expect("kernel fuzz preparation")
        .finish(payload)
        .expect("bounded fuzz block")
}

fn identity(index: usize) -> StoreBlockIdentity {
    StoreBlockIdentity::new([u8::try_from(index + 1).expect("fuzz operation identity bound"); 16])
        .expect("nonzero fuzz identity")
}

fn open<'authority, 'catalog>(
    authority: &'authority crate::StorageKernelResourceAuthority,
    retention_time: &'authority RetentionTimeAuthority,
    catalog: &'catalog Catalog<'authority>,
    scope: SegmentScope,
) -> Result<ActiveSegmentLedger<'authority, 'catalog>, super::LedgerFailure> {
    ActiveSegmentLedger::open_with_retention_time(
        authority,
        retention_time,
        catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x91; 32])),
    )
}

fn recover_or_stop<'authority, 'catalog>(
    authority: &'authority crate::StorageKernelResourceAuthority,
    retention_time: &'authority RetentionTimeAuthority,
    catalog: &'catalog Catalog<'authority>,
    scope: SegmentScope,
) -> Option<ActiveSegmentLedger<'authority, 'catalog>> {
    match open(authority, retention_time, catalog, scope) {
        Ok(ledger) => Some(ledger),
        Err(failure) if failure.code() == LedgerFailureCode::InvalidInput => None,
        Err(failure) => panic!("unexpected fuzz recovery failure: {failure:?}"),
    }
}

fn catalog_secret() -> CatalogSecret {
    CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32]))
}

fn install_retention_policy(catalog: &Catalog<'_>, instance: InstanceId, tenant: TenantId) {
    let basis = catalog.pin().expect("fuzz policy basis");
    catalog
        .commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([0x84; 16]).expect("fuzz policy transaction"),
                FormatEpoch::CATALOG_V1,
                vec![
                    CatalogObject::new(governance_policy(instance, tenant))
                        .expect("bounded fuzz policy"),
                ],
            )
            .expect("fuzz policy proposal"),
            None,
        )
        .expect("fuzz policy publication");
}

fn governance_policy(instance: InstanceId, tenant: TenantId) -> Vec<u8> {
    let slug = b"fuzz-tenant";
    let display = b"Fuzz tenant";
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"POSGOV03");
    encoded.extend_from_slice(&instance.to_bytes());
    encoded.extend_from_slice(&tenant.to_bytes());
    encoded.push(u8::try_from(slug.len()).expect("bounded fuzz slug"));
    encoded.extend_from_slice(slug);
    encoded.push(u8::try_from(display.len()).expect("bounded fuzz display"));
    encoded.extend_from_slice(display);
    encoded.extend_from_slice(&[0x11; 16]);
    encoded.extend_from_slice(&[0x21; 32]);
    encoded.extend_from_slice(&[0x22; 32]);
    encoded.extend_from_slice(&[0x12; 16]);
    encoded.extend_from_slice(&[0x23; 32]);
    encoded.extend_from_slice(&[0x24; 32]);
    encoded.extend_from_slice(&[0x13; 16]);
    encoded.extend_from_slice(&[0x25; 32]);
    encoded.extend_from_slice(&[0x26; 32]);
    encoded.extend_from_slice(&[0x27; 32]);
    encoded.extend_from_slice(&[0x28; 32]);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.push(0x29);
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    encoded.push(0x2a);
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..11 {
        encoded.extend_from_slice(&1_u64.to_be_bytes());
    }
    encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
    encoded
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
