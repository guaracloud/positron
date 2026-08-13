use super::*;

#[test]
fn recovery_reconciles_a_crash_between_the_two_seal_renames() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let committed = ledger.append(prepared(scope, b"survives-seal")?)?;
        let failure = with_ledger_fault(LedgerFileEvent::RenameSealFrontier, || ledger.seal())
            .expect_err("the interrupted seal cannot publish success");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.frontier(), committed.position());
        assert_eq!(reopened.snapshot()?.blocks()[0].payload(), b"survives-seal");
        drop(reopened);
        assert_eq!(
            ActiveSegmentLedger::open(authority, catalog, scope, key())?
                .snapshot()?
                .blocks()
                .len(),
            1
        );
        Ok(())
    })
}

#[test]
fn recovery_reconciles_physical_seal_before_catalog_publication() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let committed = ledger.append(prepared(scope, b"catalog-atomic")?)?;
        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || ledger.seal())
            .expect_err("catalog publication failure cannot report a sealed segment");
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::CommitAmbiguous
        );
        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(reopened.snapshot()?.frontier(), committed.position());
        drop(reopened);
        assert_eq!(
            ActiveSegmentLedger::open(authority, catalog, scope, key())?
                .snapshot()?
                .blocks()
                .len(),
            1
        );
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
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RecoveryRequired
        );
        assert!(
            ActiveSegmentLedger::open(
                authority,
                catalog,
                scope,
                SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
            )?
            .snapshot()?
            .blocks()
            .is_empty()
        );
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
            let committed = ledger.append(prepared(scope, b"sync-seal")?)?;
            let failure = with_ledger_fault(event, || ledger.seal())
                .expect_err("failed sync cannot publish success");
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RecoveryRequired
            );
            assert_eq!(
                ActiveSegmentLedger::open(authority, catalog, scope, key())?
                    .snapshot()?
                    .frontier(),
                committed.position()
            );
            Ok(())
        })?;
    }
    Ok(())
}
