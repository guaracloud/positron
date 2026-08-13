use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::fault::{LedgerFileEvent, with_ledger_errno, with_ledger_fault};
use crate::catalog::{CatalogFileEvent, with_catalog_fault};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskObservation, DiskPressureState, InstanceId,
    LedgerCompletionState, LedgerFailureCode, MountQualification, PreparedStoreBlock,
    PrimaryDataVolume, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};

mod sealing_faults;

fn prepared(
    scope: SegmentScope,
    payload: &[u8],
) -> Result<PreparedStoreBlock<'static>, crate::LedgerFailure> {
    let marker = payload.first().copied().unwrap_or(1).max(1);
    PreparedStoreBlock::new(
        scope,
        StoreBlockIdentity::new([marker; 16])?,
        payload.to_vec(),
    )
}

#[test]
fn failed_frame_synchronization_never_acknowledges_and_recovery_discards_its_tail()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let wrapping_key = || SegmentProtectionKey::from_owned(Box::new([0x65; 32]));
    let ledger = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    let acknowledged = ledger.append(prepared(scope, b"acknowledged")?)?;

    let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrame, || {
        ledger.append(prepared(scope, b"unacknowledged")?)
    })
    .expect_err("frame synchronization failure cannot return a receipt");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    assert_eq!(
        ledger
            .append(prepared(scope, b"must-reopen")?)
            .expect_err("a possibly mutated live segment is poisoned")
            .code(),
        LedgerFailureCode::RecoveryRequired
    );
    assert_eq!(ledger.snapshot()?.frontier(), acknowledged.position());
    assert_eq!(ledger.snapshot()?.blocks().len(), 1);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open(&authority, &catalog, scope, wrapping_key())?;
    assert_eq!(reopened.snapshot()?.frontier(), acknowledged.position());
    assert_eq!(reopened.snapshot()?.blocks().len(), 1);
    assert_eq!(reopened.snapshot()?.blocks()[0].payload(), b"acknowledged");
    Ok(())
}

#[test]
fn recovery_discards_a_partial_first_frame_without_a_frontier() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let failure = with_ledger_fault(LedgerFileEvent::PartialFrameWrite, || {
            ledger.append(prepared(scope, b"partial-first")?)
        })
        .expect_err("partial first frame cannot publish a frontier");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        drop(ledger);

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.frontier().value(), 0);
        assert!(reopened.snapshot()?.blocks().is_empty());
        Ok(())
    })
}

#[test]
fn repeated_empty_seals_and_an_interrupted_successor_append_remain_restartable()
-> Result<(), Box<dyn Error>> {
    for _ in 0..8 {
        with_fixture(|authority, catalog, scope| {
            let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));

            ActiveSegmentLedger::open(authority, catalog, scope, key())?.seal()?;
            ActiveSegmentLedger::open(authority, catalog, scope, key())?.seal()?;

            let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let acknowledged =
                ledger.append(prepared(scope, b"acknowledged-after-empty-seals")?)?;
            drop(ledger);

            let recovered = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrame, || {
                recovered.append(prepared(scope, b"interrupted-successor")?)
            })
            .expect_err("an interrupted successor append cannot acknowledge");
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RecoveryRequired
            );
            drop(recovered);

            let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let snapshot = reopened.snapshot()?;
            assert_eq!(snapshot.frontier(), acknowledged.position());
            assert_eq!(snapshot.blocks().len(), 1);
            assert_eq!(
                snapshot.blocks()[0].payload(),
                b"acknowledged-after-empty-seals"
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn append_fault_matrix_never_overstates_the_authenticated_frontier() -> Result<(), Box<dyn Error>> {
    let before_frontier = [
        (
            LedgerFileEvent::WriteFrame,
            LedgerCompletionState::RejectedBeforeMutation,
        ),
        (
            LedgerFileEvent::PartialFrameWrite,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::SynchronizeFrame,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::InspectSegmentMetadata,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::RemoveFrontierTemporary,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::CreateFrontierTemporary,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::WriteFrontier,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::PartialFrontierWrite,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::SynchronizeFrontier,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::RenameFrontier,
            LedgerCompletionState::RecoveryRequired,
        ),
    ];
    for (event, completion) in before_frontier {
        with_fixture(|authority, catalog, scope| {
            let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
            let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let first = ledger.append(prepared(scope, b"first")?)?;
            let failure = with_ledger_fault(event, || ledger.append(prepared(scope, b"second")?))
                .expect_err("injected boundary cannot acknowledge");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            assert_eq!(failure.completion_state(), completion);
            if completion == LedgerCompletionState::RecoveryRequired {
                let append_failure = ledger
                    .append(prepared(scope, b"blocked-append")?)
                    .expect_err("a mutated segment refuses another append until reopen");
                assert_eq!(append_failure.code(), LedgerFailureCode::RecoveryRequired);
                let seal_failure = ledger
                    .seal()
                    .expect_err("a mutated segment refuses sealing until reopen");
                assert_eq!(seal_failure.code(), LedgerFailureCode::RecoveryRequired);
            } else {
                drop(ledger);
            }

            let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            assert_eq!(reopened.snapshot()?.frontier(), first.position());
            assert_eq!(reopened.snapshot()?.blocks().len(), 1);
            let retried = reopened.append(prepared(scope, b"second")?)?;
            assert_eq!(retried.position().value(), first.position().value() + 1);
            assert_eq!(reopened.snapshot()?.blocks().len(), 2);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn pre_write_refusal_keeps_the_live_ledger_retryable_without_nonce_reuse()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let failure = with_ledger_fault(LedgerFileEvent::WriteFrame, || {
            ledger.append(prepared(scope, b"retry-in-place")?)
        })
        .expect_err("pre-write fault cannot acknowledge");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );
        let committed = ledger.append(prepared(scope, b"retry-in-place")?)?;
        assert_eq!(committed.position().value(), 1);
        assert_eq!(ledger.snapshot()?.blocks().len(), 1);
        Ok(())
    })
}

#[test]
fn frontier_directory_sync_failure_is_typed_as_commit_ambiguity() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        ledger.append(prepared(scope, b"first")?)?;
        let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrontierDirectory, || {
            ledger.append(prepared(scope, b"ambiguous")?)
        })
        .expect_err("directory synchronization cannot acknowledge");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::CommitAmbiguous
        );
        assert_eq!(
            ledger
                .append(prepared(scope, b"blocked-after-ambiguity")?)
                .expect_err("an ambiguous append must refuse further mutation")
                .code(),
            LedgerFailureCode::RecoveryRequired
        );
        let seal_failure = with_ledger_fault(LedgerFileEvent::RenameSealSegment, || ledger.seal())
            .expect_err("an ambiguous append must be recovered before sealing");
        assert_eq!(seal_failure.code(), LedgerFailureCode::RecoveryRequired);
        assert_eq!(
            seal_failure.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.blocks().len(), 2);
        assert_eq!(reopened.snapshot()?.blocks()[1].payload(), b"ambiguous");
        Ok(())
    })
}

#[test]
fn full_disk_is_a_stable_typed_failure_without_a_receipt() -> Result<(), Box<dyn Error>> {
    for error in [rustix::io::Errno::NOSPC, rustix::io::Errno::DQUOT] {
        with_fixture(|authority, catalog, scope| {
            let ledger = ActiveSegmentLedger::open(
                authority,
                catalog,
                scope,
                SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
            )?;
            let failure = with_ledger_errno(LedgerFileEvent::WriteFrame, error, || {
                ledger.append(prepared(scope, b"no-space")?)
            })
            .expect_err("exhausted storage cannot acknowledge");
            assert_eq!(failure.code(), LedgerFailureCode::StorageExhausted);
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RejectedBeforeMutation
            );
            assert_eq!(ledger.snapshot()?.blocks().len(), 0);
            assert_eq!(
                ledger
                    .append(prepared(scope, b"no-space")?)?
                    .position()
                    .value(),
                1
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn hard_pressure_resolves_replay_and_conflict_before_refusing_new_work()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let committed = ledger.append(prepared(scope, b"hard-pressure-committed")?)?;
        let snapshot = ledger.snapshot()?;
        let usage = authority.governor().inspect()?.outstanding_total();
        assert_eq!(
            authority.observe_disk_for_test(DiskObservation::new(0))?,
            DiskPressureState::HardPressure
        );

        assert_eq!(
            ledger.append(prepared(scope, b"hard-pressure-committed")?)?,
            committed
        );
        assert_eq!(
            ledger
                .append(prepared(scope, b"hard-pressure-conflict")?)
                .expect_err("conflict is resolved before new-work admission")
                .code(),
            LedgerFailureCode::IdempotencyConflict
        );
        assert_eq!(
            ledger
                .append(prepared(scope, b"new-work")?)
                .expect_err("hard pressure refuses new work")
                .code(),
            LedgerFailureCode::ResourceAdmissionRefused
        );
        assert_eq!(authority.governor().inspect()?.outstanding_total(), usage);
        assert_eq!(snapshot.blocks().len(), 1);
        assert_eq!(snapshot.blocks()[0].payload(), b"hard-pressure-committed");
        Ok(())
    })
}

#[test]
fn exhausted_scope_lease_inventory_refuses_before_storage_mutation() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let mut leases = Vec::new();
        for value in 0..crate::MAX_TENANT_QUOTAS {
            let mut key = [0_u8; 22];
            key[..2].copy_from_slice(&u16::try_from(value)?.to_be_bytes());
            let lease = authority
                .acquire_active_segment_ledger(key)
                .ok()
                .expect("unique bounded scope lease");
            leases.push(lease);
        }
        let failure = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )
        .expect_err("bounded scope inventory cannot grow");
        assert_eq!(failure.code(), LedgerFailureCode::LimitExceeded);
        assert!(
            authority
                .primary_data_volume()
                .expect("fixture volume")
                ._root
                .metadata()
                .is_ok()
        );
        drop(leases);
        Ok(())
    })
}

fn with_fixture<T>(
    action: impl FnOnce(
        &crate::StorageKernelResourceAuthority,
        &Catalog<'_>,
        SegmentScope,
    ) -> Result<T, Box<dyn Error>>,
) -> Result<T, Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x71; 16])?,
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    action(&authority, &catalog, scope)
}
