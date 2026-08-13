use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::support::{TemporaryRoot, establish_authority};
use crate::active_segment_ledger::fault::{
    LedgerFileEvent, with_ledger_fault, with_ledger_fault_code,
};
use crate::catalog::{CatalogFileEvent, with_catalog_fault};
use crate::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, LedgerCompletionState,
    LedgerFailureCode, MountQualification, PreparedStoreBlock, PrimaryDataVolume,
    SegmentProtectionKey, SegmentScope,
};

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
    let acknowledged = ledger.append(PreparedStoreBlock::new(b"acknowledged".to_vec())?)?;

    let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrame, || {
        ledger.append(PreparedStoreBlock::new(b"unacknowledged".to_vec())?)
    })
    .expect_err("frame synchronization failure cannot return a receipt");
    assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        failure.completion_state(),
        LedgerCompletionState::RecoveryRequired
    );
    assert_eq!(
        ledger
            .append(PreparedStoreBlock::new(b"must-reopen".to_vec())?)
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
            ledger.append(PreparedStoreBlock::new(b"partial-first".to_vec())?)
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
            let first = ledger.append(PreparedStoreBlock::new(b"first".to_vec())?)?;
            let failure = with_ledger_fault(event, || {
                ledger.append(PreparedStoreBlock::new(b"second".to_vec())?)
            })
            .expect_err("injected boundary cannot acknowledge");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            assert_eq!(failure.completion_state(), completion);
            drop(ledger);

            let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            assert_eq!(reopened.snapshot()?.frontier(), first.position());
            assert_eq!(reopened.snapshot()?.blocks().len(), 1);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn frontier_directory_sync_failure_is_typed_as_commit_ambiguity() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        ledger.append(PreparedStoreBlock::new(b"first".to_vec())?)?;
        let failure = with_ledger_fault(LedgerFileEvent::SynchronizeFrontierDirectory, || {
            ledger.append(PreparedStoreBlock::new(b"ambiguous".to_vec())?)
        })
        .expect_err("directory synchronization cannot acknowledge");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::CommitAmbiguous
        );
        drop(ledger);

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.blocks().len(), 2);
        assert_eq!(reopened.snapshot()?.blocks()[1].payload(), b"ambiguous");
        Ok(())
    })
}

#[test]
fn full_disk_is_a_stable_typed_failure_without_a_receipt() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let failure = with_ledger_fault_code(
            LedgerFileEvent::WriteFrame,
            LedgerFailureCode::StorageExhausted,
            || ledger.append(PreparedStoreBlock::new(b"no-space".to_vec())?),
        )
        .expect_err("full disk cannot acknowledge");
        assert_eq!(failure.code(), LedgerFailureCode::StorageExhausted);
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );
        assert_eq!(ledger.snapshot()?.blocks().len(), 0);
        Ok(())
    })
}

#[test]
fn recovery_reconciles_a_crash_between_the_two_seal_renames() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let committed = ledger.append(PreparedStoreBlock::new(b"survives-seal".to_vec())?)?;
        let failure = with_ledger_fault(LedgerFileEvent::RenameSealFrontier, || ledger.seal())
            .expect_err("the interrupted seal cannot publish success");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.frontier(), committed.position());
        assert_eq!(reopened.snapshot()?.blocks().len(), 1);
        assert_eq!(reopened.snapshot()?.blocks()[0].payload(), b"survives-seal");
        drop(reopened);

        let verified_again = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(verified_again.snapshot()?.blocks().len(), 1);
        Ok(())
    })
}

#[test]
fn recovery_reconciles_physical_seal_before_catalog_publication() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let committed = ledger.append(PreparedStoreBlock::new(b"catalog-atomic".to_vec())?)?;
        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || ledger.seal())
            .expect_err("catalog publication failure cannot report a sealed segment");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::CommitAmbiguous
        );

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.frontier(), committed.position());
        assert_eq!(
            reopened.snapshot()?.blocks()[0].payload(),
            b"catalog-atomic"
        );
        drop(reopened);

        let verified_again = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(verified_again.snapshot()?.blocks().len(), 1);
        Ok(())
    })
}

#[test]
fn active_segment_creation_faults_never_return_a_live_ledger() -> Result<(), Box<dyn Error>> {
    for (event, completion) in [
        (
            LedgerFileEvent::CreateSegment,
            LedgerCompletionState::RejectedBeforeMutation,
        ),
        (
            LedgerFileEvent::WriteSegmentHeader,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::PartialSegmentHeaderWrite,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::SynchronizeSegmentHeader,
            LedgerCompletionState::RecoveryRequired,
        ),
        (
            LedgerFileEvent::SynchronizeSegmentDirectory,
            LedgerCompletionState::RecoveryRequired,
        ),
    ] {
        with_fixture(|authority, catalog, scope| {
            let failure = with_ledger_fault(event, || {
                ActiveSegmentLedger::open(
                    authority,
                    catalog,
                    scope,
                    SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
                )
            })
            .expect_err("a failed create cannot expose an append authority");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            assert_eq!(failure.completion_state(), completion);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn failed_initial_catalog_publication_is_reconciled_before_its_successor()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
            ActiveSegmentLedger::open(
                authority,
                catalog,
                scope,
                SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
            )
        })
        .expect_err("failed catalog publication cannot expose a live ledger");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );

        let reopened = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        assert!(reopened.snapshot()?.blocks().is_empty());
        Ok(())
    })
}

#[test]
fn seal_directory_sync_faults_remain_restartable() -> Result<(), Box<dyn Error>> {
    for event in [
        LedgerFileEvent::SynchronizeSealedDirectory,
        LedgerFileEvent::SynchronizeActiveDirectory,
    ] {
        with_fixture(|authority, catalog, scope| {
            let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
            let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            let committed = ledger.append(PreparedStoreBlock::new(b"sync-seal".to_vec())?)?;
            let failure = with_ledger_fault(event, || ledger.seal())
                .expect_err("failed directory synchronization cannot publish success");
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RecoveryRequired
            );
            let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
            assert_eq!(reopened.snapshot()?.frontier(), committed.position());
            Ok(())
        })?;
    }
    Ok(())
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
