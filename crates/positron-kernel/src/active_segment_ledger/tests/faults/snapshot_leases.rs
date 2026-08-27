use super::super::super::fault::{LedgerFileEvent, with_ledger_fault, with_ledger_fault_sequence};
use super::*;
use crate::{
    OrdinaryPool, ResourceAmounts, ResourceDimension, SnapshotLeaseUsage, WorkClaim, WorkKind,
};

fn resize_blocker(
    authority: &crate::StorageKernelResourceAuthority,
    tenant: positron_domain::identity::TenantId,
) -> Result<crate::ResourceReservation<'_>, Box<dyn Error>> {
    let snapshot = authority.governor().inspect()?;
    let dimension = ResourceDimension::MemoryBytes;
    let shared = snapshot
        .pool_capacity(OrdinaryPool::Shared, dimension)
        .checked_sub(snapshot.pool_usage(OrdinaryPool::Shared, dimension))
        .ok_or("shared memory usage exceeds capacity")?;
    let query = snapshot
        .pool_capacity(OrdinaryPool::InteractiveQueryTail, dimension)
        .checked_sub(snapshot.pool_usage(OrdinaryPool::InteractiveQueryTail, dimension))
        .ok_or("query memory usage exceeds capacity")?;
    let amount = shared
        .checked_add(query)
        .and_then(|available| available.checked_sub(1))
        .ok_or("resize blocker cannot leave one byte of headroom")?;
    let claim = WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(dimension, amount)?,
    )?;
    Ok(authority.governor().reserve(claim)?)
}

#[test]
fn snapshot_lease_pins_exact_visibility_across_append_restart_release_and_expiry()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        ledger.append(prepared(scope, b"leased")?)?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        assert_eq!(
            format!("{lease:?}"),
            format!(
                "SnapshotLeaseGrant {{ identity: {:?}, expiry: 200, snapshot: \"<pinned>\" }}",
                lease.identity()
            )
        );
        let identity = lease.identity();
        let source_identity = lease.snapshot().catalog_identity();
        let source_generation = lease.snapshot().catalog_generation();
        assert_eq!(lease.snapshot().blocks().len(), 1);
        assert_eq!(lease.into_snapshot().blocks().len(), 1);

        ledger.append(prepared(scope, b"future")?)?;
        let resumed = ledger.resume_snapshot_lease(identity, 101)?;
        assert_eq!(resumed.snapshot().catalog_identity(), source_identity);
        assert_eq!(resumed.snapshot().catalog_generation(), source_generation);
        assert_eq!(resumed.snapshot().blocks().len(), 1);
        assert_eq!(resumed.snapshot().blocks()[0].payload(), b"leased");
        drop(resumed);
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(102),
        )?;
        let restarted = reopened.resume_snapshot_lease(identity, 102)?;
        assert_eq!(restarted.snapshot().catalog_identity(), source_identity);
        assert_eq!(restarted.snapshot().catalog_generation(), source_generation);
        assert_eq!(restarted.snapshot().blocks().len(), 1);
        drop(restarted);
        reopened.release_snapshot_lease(identity)?;
        reopened.release_snapshot_lease(identity)?;
        assert_eq!(
            reopened
                .resume_snapshot_lease(identity, 103)
                .expect_err("released lease is unavailable")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );

        let expiring = reopened.create_snapshot_lease(109, 110)?.identity();
        assert_eq!(
            reopened
                .resume_snapshot_lease(expiring, 110)
                .expect_err("expired lease is removed")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        reopened.release_snapshot_lease(expiring)?;
        Ok(())
    })
}

#[test]
fn snapshot_lease_public_time_and_signal_boundaries_are_typed_and_restartable()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        assert_eq!(
            ledger
                .create_snapshot_lease(100, 100)
                .expect_err("lease lifetime must be positive")
                .code(),
            LedgerFailureCode::InvalidInput
        );
        drop(ledger);

        let trace_scope = SegmentScope::new(scope.tenant, SignalKind::Traces, scope.shard);
        let traces = ActiveSegmentLedger::open(authority, catalog, trace_scope, key())?;
        let identity = traces.create_snapshot_lease(100, 200)?.identity();
        drop(traces);
        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            trace_scope,
            key(),
            &lease_clock(101),
        )?;
        assert_eq!(
            reopened.resume_snapshot_lease(identity, 101)?.identity(),
            identity
        );
        Ok(())
    })
}

#[test]
fn fresh_lease_rejects_expiry_before_the_recovered_clock_floor() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let held = ledger.create_snapshot_lease(100, 200)?.identity();
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        let failure = reopened
            .create_snapshot_lease(100, 101)
            .expect_err("the durable clock floor must preserve a positive lease interval");
        assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
        reopened.release_snapshot_lease(held)?;
        Ok(())
    })
}

#[test]
fn prepared_snapshot_lease_replacement_is_atomic_and_reversible() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        ledger.append(prepared(scope, b"leased")?)?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let old_identity = lease.identity();
        drop(lease);
        ledger.append(prepared(scope, b"future")?)?;

        let mut failed = ledger.prepare_snapshot_lease_replacement(old_identity, 101, 200)?;
        assert_eq!(failed.old_identity(), old_identity);
        assert_eq!(
            failed
                .snapshot()
                .ok_or("candidate snapshot")?
                .frontier()
                .value(),
            2
        );
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || failed.commit())
            .expect_err("a replacement publication fault must preserve the old lease");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        drop(failed);
        assert_eq!(
            ledger
                .resume_snapshot_lease(old_identity, 101)?
                .snapshot()
                .frontier()
                .value(),
            1
        );
        ledger.release_snapshot_lease(old_identity)?;

        let old = ledger.create_snapshot_lease(102, 200)?;
        let old_identity = old.identity();
        drop(old);
        let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 103, 200)?;
        let grant = replacement.commit()?;
        let new_identity = grant.identity();
        drop(grant);
        assert!(replacement.snapshot().is_none());
        assert_eq!(
            ledger
                .resume_snapshot_lease(old_identity, 103)
                .expect_err("committed replacement must retire its old identity")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        replacement.rollback()?;
        assert_eq!(
            ledger.resume_snapshot_lease(old_identity, 104)?.identity(),
            old_identity
        );
        ledger.release_snapshot_lease(old_identity)?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(new_identity, 104)
                .expect_err("rolled back replacement must retire its new identity")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn prepared_snapshot_lease_replacement_rejects_stale_and_invalid_transitions()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x76; 32])),
        )?;
        ledger.append(prepared(scope, b"leased")?)?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let old_identity = lease.identity();
        drop(lease);
        let failure = ledger
            .prepare_snapshot_lease_replacement(old_identity, 100, 100)
            .err()
            .ok_or("an empty replacement interval unexpectedly succeeded")?;
        assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
        assert!(
            ledger
                .prepare_snapshot_lease_replacement(old_identity, 99, 200)
                .is_err()
        );
        drop(ledger.resume_snapshot_lease(old_identity, 101)?);
        let failure = ledger
            .prepare_snapshot_lease_replacement(old_identity, 100, 101)
            .err()
            .ok_or("the recovered clock floor unexpectedly allowed an empty interval")?;
        assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
        ledger.append(prepared(scope, b"future")?)?;

        let mut stale = ledger.prepare_snapshot_lease_replacement(old_identity, 102, 200)?;
        ledger.record_snapshot_lease_usage(
            old_identity,
            SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0),
        )?;
        assert_eq!(
            stale
                .commit()
                .expect_err("a changed old record must not be overwritten")
                .code(),
            LedgerFailureCode::ConcurrentWriter
        );
        assert!(stale.rollback().is_ok());
        drop(stale);

        let missing = ledger.create_snapshot_lease(103, 200)?;
        let missing_identity = missing.identity();
        drop(missing);
        let mut missing_replacement =
            ledger.prepare_snapshot_lease_replacement(missing_identity, 104, 200)?;
        ledger.release_snapshot_lease(missing_identity)?;
        assert_eq!(
            missing_replacement
                .commit()
                .expect_err("a retired old identity cannot be replaced")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        drop(missing_replacement);

        let old = ledger.create_snapshot_lease(105, 200)?;
        let old_identity = old.identity();
        drop(old);
        let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 106, 200)?;
        assert!(replacement.rollback().is_ok());
        let grant = replacement.commit()?;
        let new_identity = grant.identity();
        drop(grant);
        assert!(replacement.commit().is_err());
        replacement.rollback()?;
        assert!(replacement.rollback().is_ok());
        ledger.release_snapshot_lease(old_identity)?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(new_identity, 107)
                .expect_err("rollback must retire the candidate identity")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );

        let old = ledger.create_snapshot_lease(108, 200)?;
        let old_identity = old.identity();
        drop(old);
        let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 109, 200)?;
        let grant = replacement.commit()?;
        let new_identity = grant.identity();
        drop(grant);
        ledger.release_snapshot_lease(new_identity)?;
        assert_eq!(
            replacement
                .rollback()
                .expect_err("a retired candidate cannot be rolled back")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );

        let old = ledger.create_snapshot_lease(110, 200)?;
        let old_identity = old.identity();
        drop(old);
        let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 111, 200)?;
        let grant = replacement.commit()?;
        let new_identity = grant.identity();
        drop(grant);
        ledger.record_snapshot_lease_usage(
            new_identity,
            SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0),
        )?;
        assert_eq!(
            replacement
                .rollback()
                .expect_err("a changed candidate must not be overwritten")
                .code(),
            LedgerFailureCode::ConcurrentWriter
        );
        ledger.release_snapshot_lease(new_identity)?;

        let old = ledger.create_snapshot_lease(112, 200)?;
        let old_identity = old.identity();
        drop(old);
        let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 113, 200)?;
        let grant = replacement.commit()?;
        let new_identity = grant.identity();
        drop(grant);
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            replacement.rollback()
        })
        .expect_err("a rollback publication fault must remain retryable");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        replacement.rollback()?;
        ledger.release_snapshot_lease(old_identity)?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(new_identity, 114)
                .expect_err("a successful rollback removes the candidate")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn prepared_snapshot_lease_replacement_refusal_restores_its_reservation()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x77; 32])),
        )?;
        ledger.append(prepared(scope, b"leased")?)?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        drop(lease);
        ledger.append(prepared(scope, b"future")?)?;
        let mut replacement = ledger.prepare_snapshot_lease_replacement(identity, 101, 200)?;
        let blocker = resize_blocker(authority, scope.tenant)?;
        let failure = replacement
            .commit()
            .expect_err("replacement growth must refuse under bounded pressure");
        assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
        drop(blocker);
        assert_eq!(
            ledger.resume_snapshot_lease(identity, 102)?.identity(),
            identity
        );
        ledger.release_snapshot_lease(identity)?;
        Ok(())
    })
}

#[test]
fn committed_replacement_rollback_refusal_preserves_the_candidate_until_capacity_returns()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x79; 32])),
        )?;
        ledger.append(prepared(scope, b"leased")?)?;
        let old_identity = ledger.create_snapshot_lease(100, 200)?.identity();
        ledger.record_snapshot_lease_usage(
            old_identity,
            SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7),
        )?;
        ledger.append(prepared(scope, b"future")?)?;

        let mut replacement = ledger.prepare_snapshot_lease_replacement(old_identity, 101, 200)?;
        let grant = replacement.commit()?;
        let new_identity = grant.identity();
        drop(grant);

        let blocker = resize_blocker(authority, scope.tenant)?;
        let refusal = replacement
            .rollback()
            .expect_err("rollback growth must refuse under bounded pressure");
        assert_eq!(refusal.code(), LedgerFailureCode::ResourceAdmissionRefused);
        assert_eq!(
            ledger
                .resume_snapshot_lease(old_identity, 102)
                .expect_err("the old identity stays retired while rollback is pending")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        drop(blocker);

        replacement.rollback()?;
        assert_eq!(
            ledger.resume_snapshot_lease(old_identity, 103)?.identity(),
            old_identity
        );
        assert_eq!(
            ledger
                .resume_snapshot_lease(new_identity, 103)
                .expect_err("a successful rollback removes the candidate")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        ledger.release_snapshot_lease(old_identity)?;
        Ok(())
    })
}

#[test]
fn prepared_snapshot_lease_replacement_rejects_a_durable_expiry() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x78; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0x78, |bytes| {
            bytes[103..111].copy_from_slice(&101_u64.to_be_bytes());
        })?;
        let failure = ledger
            .prepare_snapshot_lease_replacement(identity, 101, 200)
            .err()
            .ok_or("replacement must reject a durable lease expired at observation time")?;
        assert_eq!(failure.code(), LedgerFailureCode::SnapshotExpired);
        Ok(())
    })
}

#[test]
fn snapshot_lease_ttl_ceiling_is_exact_and_rejection_precedes_all_mutation()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let before_catalog = catalog.pin()?;
        let before_resources = authority.governor().inspect()?;
        assert_eq!(
            ledger
                .create_snapshot_lease(100, 3_701)
                .expect_err("lease above the one-hour ceiling")
                .code(),
            LedgerFailureCode::InvalidInput
        );
        let after_catalog = catalog.pin()?;
        assert_eq!(after_catalog.identity(), before_catalog.identity());
        assert_eq!(after_catalog.number(), before_catalog.number());
        let after_resources = authority.governor().inspect()?;
        assert_eq!(
            after_resources.outstanding_total(),
            before_resources.outstanding_total()
        );
        for dimension in crate::ResourceDimension::ALL {
            assert_eq!(
                after_resources.usage(dimension),
                before_resources.usage(dimension)
            );
        }

        let exact = ledger.create_snapshot_lease(100, 3_700)?;
        ledger.release_snapshot_lease(exact.identity())?;
        let maximum = ledger.create_snapshot_lease(u64::MAX - 3_600, u64::MAX)?;
        ledger.release_snapshot_lease(maximum.identity())?;
        assert_eq!(
            ledger
                .create_snapshot_lease(0, u64::MAX)
                .expect_err("checked lifetime arithmetic rejects an overlong interval")
                .code(),
            LedgerFailureCode::InvalidInput
        );
        Ok(())
    })
}

#[test]
fn snapshot_lease_creation_prunes_expired_capacity_without_releasing_active_leases()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let active = ledger.create_snapshot_lease(100, 1_000)?.identity();
        for now in 101..=165 {
            let _expired = ledger.create_snapshot_lease(now, now + 1)?;
        }
        assert_eq!(
            ledger.resume_snapshot_lease(active, 166)?.identity(),
            active
        );
        Ok(())
    })
}

#[test]
fn durable_lease_inventory_cap_and_missing_reservation_fail_closed() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let template_identity = ledger.create_snapshot_lease(100, 1_000)?.identity();
        let template = catalog
            .pin()?
            .plaintext_objects()
            .find(|bytes| bytes.starts_with(b"PSLEASE1"))
            .ok_or("snapshot lease catalog record missing")?
            .to_vec();
        ledger.release_snapshot_lease(template_identity)?;

        let basis = catalog.pin()?;
        let mut objects = basis
            .plaintext_objects()
            .map(|bytes| CatalogObject::new(bytes.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        for identity in 1_u8..=64 {
            let mut bytes = template.clone();
            bytes[10..26].copy_from_slice(&[identity; 16]);
            objects.push(CatalogObject::new(bytes)?);
        }
        catalog.commit(
            basis.identity(),
            CatalogProposal::new(
                TransactionId::new([0xe4; 16])?,
                FormatEpoch::new(1)?,
                objects,
            )?,
            None,
        )?;

        assert_eq!(
            ledger
                .create_snapshot_lease(200, 1_000)
                .expect_err("the 65th active durable lease exceeds the hard cap")
                .code(),
            LedgerFailureCode::LimitExceeded
        );
        let missing_reservation = crate::SnapshotLeaseId::new([1; 16])?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(missing_reservation, 200)
                .expect_err("a durable lease without a live reservation is corrupt")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
        assert_eq!(
            ledger
                .snapshot_lease_usage(missing_reservation, 200)
                .expect_err("usage reads must reject a missing live reservation")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
        assert_eq!(
            ledger
                .record_snapshot_lease_usage(
                    missing_reservation,
                    SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0),
                )
                .expect_err("usage writes must reject a missing live reservation")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
        Ok(())
    })
}

#[test]
fn snapshot_lease_resume_fails_closed_on_bad_durable_shapes() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        ledger.append(prepared(scope, b"leased")?)?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xe1, |bytes| bytes[113] ^= 1)?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("a mismatched durable block identity must fail closed")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
        Ok(())
    })?;

    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        ledger.append(prepared(scope, b"leased")?)?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xe2, |bytes| {
            bytes[87..95].copy_from_slice(&u64::MAX.to_be_bytes());
        })?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("a frontier beyond the live ledger must fail closed")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn expired_markers_are_bounded_across_repeated_expiry_and_reopen() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let baseline = authority.governor().inspect()?;

        for now in 100..=160 {
            let identity = ledger.create_snapshot_lease(now, now + 1)?.identity();
            let first =
                ledger.resume_snapshot_lease_with_marker(identity, now, 1, [now as u8; 32])?;
            assert_eq!(first.resume_count(), 1);
            drop(first);
            let repeated =
                ledger.resume_snapshot_lease_with_marker(identity, now, 1, [now as u8; 32])?;
            assert_eq!(repeated.resume_count(), 2);
            drop(repeated);
            if now < 160 {
                let next = ledger.create_snapshot_lease(now + 1, now + 2)?.identity();
                assert_ne!(next, identity);
                ledger.release_snapshot_lease(next)?;
            }
        }

        let expired = ledger
            .resume_snapshot_lease(crate::SnapshotLeaseId::new([0x01; 16])?, 161)
            .expect_err("the synthetic identity is not a durable lease");
        assert_eq!(expired.code(), LedgerFailureCode::SnapshotExpired);
        assert_eq!(
            catalog
                .pin()?
                .plaintext_objects()
                .filter(|bytes| bytes.starts_with(b"PSLEASE1"))
                .count(),
            0
        );
        assert_eq!(
            authority.governor().inspect()?.outstanding_total(),
            baseline.outstanding_total()
        );
        for dimension in ResourceDimension::ALL {
            assert_eq!(
                authority.governor().inspect()?.usage(dimension),
                baseline.usage(dimension)
            );
        }

        drop(ledger);
        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(161),
        )?;
        assert_eq!(
            catalog
                .pin()?
                .plaintext_objects()
                .filter(|bytes| bytes.starts_with(b"PSLEASE1"))
                .count(),
            0
        );
        drop(reopened);
        Ok(())
    })
}

#[test]
fn refused_snapshot_capacity_never_publishes_or_retains_a_lease() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        ledger.append(prepared(scope, b"snapshot-capacity")?)?;
        let held = authority.governor().reserve(crate::WorkClaim::tenant(
            scope.tenant,
            crate::WorkKind::InteractiveQueryTail,
            crate::ResourceAmounts::only(crate::ResourceDimension::QueueSlots, 16)?,
        )?)?;
        let baseline = authority.governor().inspect()?.outstanding_total();

        for now in 100..=164 {
            assert_eq!(
                ledger
                    .create_snapshot_lease(now, now + 100)
                    .expect_err("snapshot capacity is unavailable")
                    .code(),
                LedgerFailureCode::ResourceAdmissionRefused
            );
            assert_eq!(
                authority.governor().inspect()?.outstanding_total(),
                baseline
            );
            assert_eq!(
                catalog
                    .pin()?
                    .plaintext_objects()
                    .filter(|bytes| bytes.starts_with(b"PSLEASE1"))
                    .count(),
                0
            );
        }

        drop(held);
        let lease = ledger.create_snapshot_lease(165, 265)?;
        ledger.release_snapshot_lease(lease.identity())?;
        Ok(())
    })
}

#[test]
fn snapshot_lease_pruning_is_restart_safe_atomic_and_rejects_time_regression()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let active = ledger.create_snapshot_lease(100, 1_000)?.identity();
        let _expired = ledger.create_snapshot_lease(101, 102)?;
        drop(ledger);

        let regressed = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(100),
        )
        .err()
        .ok_or("restart accepted a regressed durable lease clock")?;
        assert_eq!(regressed.code(), LedgerFailureCode::InvalidInput);
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            ActiveSegmentLedger::open_with_clock(
                authority,
                catalog,
                scope,
                key(),
                &lease_clock(102),
            )
        })
        .err()
        .ok_or("failed restart pruning unexpectedly opened the ledger")?;
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(103),
        )?;
        assert_eq!(
            reopened.resume_snapshot_lease(active, 103)?.identity(),
            active
        );
        let replacement = reopened.create_snapshot_lease(103, 200)?.identity();
        assert_eq!(
            reopened.resume_snapshot_lease(replacement, 103)?.identity(),
            replacement
        );
        assert_eq!(
            reopened
                .resume_snapshot_lease(active, 102)
                .expect_err("durable lease time cannot move backwards")
                .code(),
            LedgerFailureCode::InvalidInput
        );
        Ok(())
    })
}

#[test]
fn restart_prunes_expired_leases_before_reduced_capacity_reservation() -> Result<(), Box<dyn Error>>
{
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let expired = ledger.create_snapshot_lease(100, 150)?.identity();
        let active = ledger.create_snapshot_lease(101, 1_000)?.identity();
        drop(ledger);

        let held = authority.governor().reserve(crate::WorkClaim::tenant(
            scope.tenant,
            crate::WorkKind::InteractiveQueryTail,
            crate::ResourceAmounts::only(crate::ResourceDimension::LeaseSlots, 5)?,
        )?)?;
        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(200),
        )?;
        assert_eq!(
            reopened.resume_snapshot_lease(active, 200)?.identity(),
            active
        );
        assert_eq!(
            reopened
                .resume_snapshot_lease(expired, 200)
                .expect_err("restart prunes the expired lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        drop(held);
        Ok(())
    })
}

#[test]
fn snapshot_lease_release_fault_retains_retryable_idempotent_truth() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            ledger.release_snapshot_lease(identity)
        })
        .expect_err("failed release cannot erase durable resume truth");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("resume retries the registered cleanup intent")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        ledger.release_snapshot_lease(identity)?;
        ledger.release_snapshot_lease(identity)?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 102)
                .expect_err("idempotent release remains terminal")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn later_lease_activity_retries_a_failed_release_without_losing_its_identity()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            ledger.release_snapshot_lease(identity)
        })
        .expect_err("failed release stays pending in the ledger authority");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);

        let replacement = ledger.create_snapshot_lease(101, 201)?.identity();
        assert_eq!(
            ledger.resume_snapshot_lease(replacement, 101)?.identity(),
            replacement
        );
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("later lease activity drains the pending release")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn snapshot_lease_v1_catalog_record_remains_restart_resumable() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xc1, |bytes| {
            bytes.splice(8..10, 1_u16.to_be_bytes());
            bytes.drain(95..103);
        })?;
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        let resumed = reopened.resume_snapshot_lease(identity, 101)?;
        assert_eq!(resumed.identity(), identity);
        assert_eq!(resumed.expiry(), 200);
        let normalized_snapshot = catalog.pin()?;
        let normalized = normalized_snapshot
            .plaintext_objects()
            .find(|bytes| bytes.starts_with(b"PSLEASE1"))
            .ok_or("normalized snapshot lease missing")?;
        assert_eq!(normalized.get(8..10), Some(2_u16.to_be_bytes().as_slice()));
        Ok(())
    })
}

#[test]
fn legacy_snapshot_lease_recovery_rejects_only_unprovable_active_ttl() -> Result<(), Box<dyn Error>>
{
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xc2, |bytes| rewrite_v2_lease_as_v1(bytes, 3_702))?;
        drop(ledger);

        let failure = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )
        .err()
        .ok_or("overlong active legacy lease unexpectedly reopened")?;
        assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
        assert!(catalog.pin()?.plaintext_objects().any(|bytes| {
            bytes.starts_with(b"PSLEASE1")
                && bytes.get(8..10) == Some(1_u16.to_be_bytes().as_slice())
        }));
        assert_ne!(identity.to_bytes(), [0; 16]);
        Ok(())
    })?;

    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xc3, |bytes| rewrite_v2_lease_as_v1(bytes, 100))?;
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        assert_eq!(
            reopened
                .resume_snapshot_lease(identity, 101)
                .expect_err("expired legacy lease must be pruned normally")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        Ok(())
    })
}

#[test]
fn maximum_v2_snapshot_lease_remains_restart_resumable() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 3_700)?.identity();
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        let resumed = reopened.resume_snapshot_lease(identity, 101)?;
        assert_eq!(resumed.expiry(), 3_700);
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_persists_ambiguous_resume_counts_across_restart()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let first = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;
        assert_eq!(first.resume_count(), 1);
        assert_eq!(first.repeated_batch_count(), 0);
        drop(first);
        let second = ledger.resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])?;
        assert_eq!(second.resume_count(), 2);
        assert_eq!(second.repeated_batch_count(), 1);
        drop(second);
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(103),
        )?;
        let third = reopened.resume_snapshot_lease_with_marker(identity, 103, 1, [9; 32])?;
        assert_eq!(third.resume_count(), 3);
        assert_eq!(third.repeated_batch_count(), 2);
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_rejects_a_second_live_attempt() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        let first = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;

        let second = ledger
            .resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])
            .expect_err("a lease cannot admit a second live attempt");
        assert_eq!(second.code(), LedgerFailureCode::ConcurrentWriter);
        drop(first);
        Ok(())
    })
}

#[test]
fn marked_usage_rejects_legacy_writes_while_the_attempt_is_live() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        let marked = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;
        let failure = ledger
            .record_snapshot_lease_usage(identity, SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0))
            .expect_err("a legacy usage writer cannot race a marked attempt");
        assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
        drop(marked);
        Ok(())
    })
}

#[test]
fn marked_usage_replays_are_idempotent_and_reject_divergent_bases() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        let mut marked = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;
        let attempt = marked
            .take_attempt()
            .ok_or("marked resume did not retain its attempt guard")?;
        let previous = marked.usage();
        let delta = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7);

        let first = ledger.record_snapshot_lease_usage_for_attempt(&attempt, previous, delta)?;
        assert_eq!(first, previous.merge(delta)?);
        assert_eq!(
            ledger.record_snapshot_lease_usage_for_attempt(&attempt, previous, delta)?,
            first
        );
        let divergent = ledger
            .record_snapshot_lease_usage_for_attempt(
                &attempt,
                previous,
                SnapshotLeaseUsage::new(2, 2, 3, 4, 5, 6, 7),
            )
            .expect_err("a retry with an obsolete usage base must not merge twice");
        assert_eq!(divergent.code(), LedgerFailureCode::ConcurrentWriter);
        Ok(())
    })
}

#[test]
fn usage_attempt_from_a_reopened_ledger_is_rejected() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let mut marked = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;
        let previous = marked.usage();
        let attempt = marked
            .take_attempt()
            .ok_or("marked resume did not retain its attempt guard")?;
        drop(marked);
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        let failure = reopened
            .record_snapshot_lease_usage_for_attempt(
                &attempt,
                previous,
                SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0),
            )
            .expect_err("an attempt guard cannot cross a ledger reopen");
        assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
        Ok(())
    })
}

#[test]
fn marked_usage_rejects_a_durable_resume_count_change() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let mut marked = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;
        let previous = marked.usage();
        let attempt = marked
            .take_attempt()
            .ok_or("marked resume did not retain its attempt guard")?;
        publish_lease_rewrite(catalog, 0xe5, |bytes| {
            bytes[111..119].copy_from_slice(&2_u64.to_be_bytes());
        })?;
        let failure = ledger
            .record_snapshot_lease_usage_for_attempt(
                &attempt,
                previous,
                SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0),
            )
            .expect_err("usage must reject a durable marker from another attempt");
        assert_eq!(failure.code(), LedgerFailureCode::ConcurrentWriter);
        Ok(())
    })
}

#[test]
fn marked_resume_reports_expiry_cleanup_publication_failure() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let _expired = ledger.create_snapshot_lease(100, 101)?;
        let active = ledger.create_snapshot_lease(100, 200)?.identity();
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            ledger.resume_snapshot_lease_with_marker(active, 101, 1, [9; 32])
        })
        .expect_err("expiry cleanup must remain ambiguous when its publication sync fails");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        let resumed = ledger.resume_snapshot_lease_with_marker(active, 102, 1, [9; 32])?;
        assert_eq!(resumed.resume_count(), 1);
        Ok(())
    })
}

#[test]
fn marked_resume_releases_expiry_cleanup_after_a_definitive_publication_failure()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let _expired = ledger.create_snapshot_lease(100, 101)?;
        let active = ledger.create_snapshot_lease(100, 200)?.identity();
        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
            ledger.resume_snapshot_lease_with_marker(active, 101, 1, [9; 32])
        })
        .expect_err("definitive expiry cleanup failures must be returned before mutation");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            failure.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );
        let resumed = ledger.resume_snapshot_lease_with_marker(active, 102, 1, [9; 32])?;
        assert_eq!(resumed.resume_count(), 1);
        Ok(())
    })
}

#[test]
fn durable_marker_sequence_cannot_be_rewound_by_a_stale_cache() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        let first = ledger.resume_snapshot_lease_with_marker(identity, 101, 5, [9; 32])?;
        drop(first);
        publish_lease_rewrite(catalog, 0xaa, |bytes| {
            bytes[127..135].copy_from_slice(&7_u64.to_be_bytes());
        })?;

        let failure = ledger
            .resume_snapshot_lease_with_marker(identity, 102, 6, [9; 32])
            .expect_err("durable marker order must outrank an older cache");
        assert_eq!(failure.code(), LedgerFailureCode::StaleResumeMarker);
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_rejects_a_stale_catalog_before_marker_publication()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        let expected_catalog = lease.snapshot().catalog_identity();
        let expected_generation = lease.snapshot().catalog_generation();
        drop(lease);

        publish_lease_rewrite(catalog, 0xa8, |_| {})?;
        let failure = ledger
            .resume_snapshot_lease_with_marker_at_catalog(
                identity,
                101,
                1,
                [9; 32],
                expected_catalog,
                expected_generation,
            )
            .expect_err("a changed Catalog generation must fence marker admission");
        assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);

        let resumed = ledger.resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])?;
        assert_eq!(resumed.resume_count(), 1);
        assert_eq!(resumed.repeated_batch_count(), 0);
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_prunes_an_unrelated_expired_lease_before_marker_admission()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let _expired = ledger.create_snapshot_lease(100, 101)?;
        let active = ledger.create_snapshot_lease(100, 200)?;
        let identity = active.identity();
        let expected = ledger.current_catalog_snapshot()?;
        let expected_catalog = expected.identity();
        let expected_generation = expected.number();
        drop(active);

        let resumed = ledger
            .resume_snapshot_lease_with_marker_at_catalog(
                identity,
                101,
                1,
                [9; 32],
                expected_catalog,
                expected_generation,
            )
            .expect("internal expiry pruning must not stale its own marker basis");
        assert_eq!(resumed.resume_count(), 1);
        assert_eq!(resumed.repeated_batch_count(), 0);
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_rejects_a_catalog_transition_at_marker_publication()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        let identity = lease.identity();
        let expected_catalog = lease.snapshot().catalog_identity();
        let expected_generation = lease.snapshot().catalog_generation();
        drop(lease);

        let failure = with_catalog_fault_hook_after(
            CatalogFileEvent::BeforeLeaseMarkerBasis,
            0,
            |catalog| publish_lease_rewrite(catalog, 0xa9, |_| {}).expect("lifecycle transition"),
            || {
                ledger.resume_snapshot_lease_with_marker_at_catalog(
                    identity,
                    101,
                    1,
                    [9; 32],
                    expected_catalog,
                    expected_generation,
                )
            },
        )
        .expect_err("a transition during marker admission must fence publication");
        assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);

        let resumed = ledger.resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])?;
        assert_eq!(resumed.resume_count(), 1);
        assert_eq!(resumed.repeated_batch_count(), 0);
        Ok(())
    })
}

#[test]
fn stale_resume_markers_are_invalid_cursor_failures() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        ledger.resume_snapshot_lease_with_marker(identity, 101, 2, [9; 32])?;

        assert_eq!(
            ledger
                .resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])
                .expect_err("a cursor behind the durable boundary must be rejected")
                .code(),
            LedgerFailureCode::StaleResumeMarker
        );
        assert_eq!(
            ledger
                .resume_snapshot_lease_with_marker(identity, 103, 2, [8; 32])
                .expect_err("a conflicting cursor at the durable boundary must be rejected")
                .code(),
            LedgerFailureCode::StaleResumeMarker
        );
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_reserves_its_added_persistent_metadata() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let before = authority.governor().inspect()?;
        let marked = ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])?;
        drop(marked);
        let after = authority.governor().inspect()?;
        assert_eq!(
            after.usage(ResourceDimension::MemoryBytes)
                - before.usage(ResourceDimension::MemoryBytes),
            56
        );
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_refuses_when_added_metadata_cannot_be_admitted()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let before = authority.governor().inspect()?;
        let remaining = before
            .pool_capacity(OrdinaryPool::Shared, ResourceDimension::MemoryBytes)
            .checked_sub(before.pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes))
            .and_then(|value| value.checked_sub(1))
            .ok_or("fixture has no memory headroom for the blocker")?;
        let blocker = authority.governor().reserve(WorkClaim::tenant(
            scope.tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, remaining)?,
        )?)?;
        let failure = ledger
            .resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])
            .expect_err("marker metadata must be admitted before publication");
        assert_eq!(failure.code(), LedgerFailureCode::ResourceAdmissionRefused);
        drop(blocker);
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_publication_failure_rolls_back_capacity_resize()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let before = authority.governor().inspect()?;
        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
            ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])
        })
        .expect_err("marker publication fault must not acknowledge the marker");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        let after = authority.governor().inspect()?;
        assert_eq!(
            after.usage(ResourceDimension::MemoryBytes),
            before.usage(ResourceDimension::MemoryBytes)
        );
        assert_eq!(
            ledger
                .resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])?
                .resume_count(),
            1
        );
        Ok(())
    })
}

#[test]
fn marked_snapshot_lease_post_rename_sync_reconciles_before_retry_and_reopen()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let first = with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
            ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])
        })
        .expect("a visible marker must reconcile as a successful publication");
        assert_eq!(first.resume_count(), 1);
        drop(first);

        let retry = ledger.resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])?;
        assert_eq!(retry.resume_count(), 2);
        assert_eq!(retry.repeated_batch_count(), 1);
        drop(retry);
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(103),
        )?;
        let restarted = reopened.resume_snapshot_lease_with_marker(identity, 103, 1, [9; 32])?;
        assert_eq!(restarted.resume_count(), 3);
        assert_eq!(restarted.repeated_batch_count(), 2);
        Ok(())
    })
}

#[test]
fn snapshot_lease_usage_is_monotonic_and_survives_reopen() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        ledger
            .record_snapshot_lease_usage(identity, SnapshotLeaseUsage::new(10, 2, 3, 4, 5, 6, 7))?;
        ledger
            .record_snapshot_lease_usage(identity, SnapshotLeaseUsage::new(11, 1, 2, 3, 4, 5, 9))?;
        let usage = ledger.snapshot_lease_usage(identity, 101)?;
        assert_eq!(usage.scanned_bytes(), 21);
        assert_eq!(usage.decoded_records(), 3);
        assert_eq!(usage.cpu_work_units(), 5);
        assert_eq!(usage.wall_seconds(), 7);
        assert_eq!(usage.output_rows(), 9);
        assert_eq!(usage.output_bytes(), 11);
        assert_eq!(usage.memory_peak_bytes(), 9);
        drop(ledger);

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(102),
        )?;
        assert_eq!(reopened.snapshot_lease_usage(identity, 102)?, usage);
        Ok(())
    })
}

#[test]
fn snapshot_lease_usage_failures_are_typed_and_publication_is_retryable()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 101)?.identity();
        assert_eq!(
            ledger
                .snapshot_lease_usage(identity, 99)
                .expect_err("usage reads must reject a clock regression")
                .code(),
            LedgerFailureCode::InvalidInput
        );
        assert_eq!(
            ledger
                .snapshot_lease_usage(identity, 101)
                .expect_err("usage reads must reject an expired lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );
        drop(ledger);
        let ledger = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        assert_eq!(
            ledger
                .record_snapshot_lease_usage(
                    identity,
                    SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0),
                )
                .expect_err("usage writes must reject an expired lease")
                .code(),
            LedgerFailureCode::SnapshotExpired
        );

        let live = ledger.create_snapshot_lease(102, 200)?.identity();
        let zero = ledger.record_snapshot_lease_usage(live, SnapshotLeaseUsage::default())?;
        assert_eq!(zero, SnapshotLeaseUsage::default());
        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
            ledger.record_snapshot_lease_usage(live, SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7))
        })
        .expect_err("a failed usage publication must remain retryable");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        let usage = ledger
            .record_snapshot_lease_usage(live, SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7))?;
        assert_eq!(usage.scanned_bytes(), 1);
        assert_eq!(usage.memory_peak_bytes(), 7);

        let reconciled =
            with_catalog_fault(CatalogFileEvent::SynchronizeGenerationDirectory, || {
                ledger
                    .record_snapshot_lease_usage(live, SnapshotLeaseUsage::new(1, 1, 1, 1, 1, 1, 1))
            })?;
        assert_eq!(reconciled.scanned_bytes(), 2);
        assert_eq!(ledger.snapshot_lease_usage(live, 103)?, reconciled);
        drop(ledger);
        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(104),
        )?;
        assert_eq!(reopened.snapshot_lease_usage(live, 104)?, reconciled);
        Ok(())
    })
}

#[test]
fn snapshot_lease_usage_writes_reject_a_durable_expiry_at_the_observed_time()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        drop(ledger.resume_snapshot_lease(identity, 101)?);
        drop(ledger);
        publish_lease_rewrite(catalog, 0xe7, |bytes| {
            bytes[103..111].copy_from_slice(&101_u64.to_be_bytes());
        })?;

        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &lease_clock(101),
        )?;
        let failure = reopened
            .record_snapshot_lease_usage(identity, SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0))
            .expect_err("usage must reject an expired durable lease");
        assert_eq!(failure.code(), LedgerFailureCode::SnapshotExpired);
        Ok(())
    })
}

#[test]
fn snapshot_lease_usage_ambiguous_publication_reconciles_durable_truth()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let delta = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7);

        let usage = with_ledger_fault(LedgerFileEvent::AfterLeaseUsagePublication, || {
            ledger.record_snapshot_lease_usage(identity, delta)
        })?;
        assert_eq!(usage, delta);
        assert_eq!(ledger.snapshot_lease_usage(identity, 101)?, delta);
        Ok(())
    })
}

#[test]
fn snapshot_lease_usage_retries_after_an_ambiguous_prepublication() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let delta = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7);

        let usage = with_ledger_fault(LedgerFileEvent::BeforeLeaseUsagePublication, || {
            ledger.record_snapshot_lease_usage(identity, delta)
        })?;
        assert_eq!(usage, delta);
        assert_eq!(ledger.snapshot_lease_usage(identity, 101)?, delta);
        Ok(())
    })
}

#[test]
fn snapshot_lease_usage_retry_failure_restores_the_original_reservation()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let baseline = authority.governor().inspect()?;
        let delta = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7);

        for _ in 0..65 {
            let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
                with_ledger_fault_sequence(
                    &[
                        LedgerFileEvent::BeforeLeaseUsagePublication,
                        LedgerFileEvent::BeforeLeaseUsageReconciliation,
                    ],
                    || ledger.record_snapshot_lease_usage(identity, delta),
                )
            })
            .expect_err("a definitive retry failure must remain typed");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            assert_eq!(
                ledger.snapshot_lease_usage(identity, 101)?,
                SnapshotLeaseUsage::default()
            );
            let after = authority.governor().inspect()?;
            assert_eq!(after.outstanding_total(), baseline.outstanding_total());
            for dimension in ResourceDimension::ALL {
                assert_eq!(after.usage(dimension), baseline.usage(dimension));
            }
        }
        Ok(())
    })
}

#[test]
fn snapshot_lease_marker_retry_failure_restores_the_original_reservation()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let before_catalog = catalog
            .pin()?
            .plaintext_objects()
            .find(|bytes| bytes.starts_with(b"PSLEASE1"))
            .ok_or("lease missing")?
            .to_vec();
        let baseline = authority.governor().inspect()?;

        for _ in 0..65 {
            let ambiguous =
                with_ledger_fault(LedgerFileEvent::BeforeLeaseMarkerPublication, || {
                    ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])
                })
                .expect_err("an unproven marker publication must be typed");
            assert_eq!(ambiguous.code(), LedgerFailureCode::StorageUnavailable);
            let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
                ledger.resume_snapshot_lease_with_marker(identity, 101, 1, [9; 32])
            })
            .expect_err("the definitive retry failure must be typed");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            let after = authority.governor().inspect()?;
            assert_eq!(after.outstanding_total(), baseline.outstanding_total());
            for dimension in ResourceDimension::ALL {
                assert_eq!(after.usage(dimension), baseline.usage(dimension));
            }
            let snapshot = catalog.pin()?;
            let durable = snapshot
                .plaintext_objects()
                .find(|bytes| bytes.starts_with(b"PSLEASE1"))
                .ok_or("lease missing after failed retry")?;
            assert_eq!(durable, before_catalog.as_slice());
        }
        Ok(())
    })
}

#[cfg(feature = "test-support")]
#[test]
fn snapshot_lease_marker_test_support_rejects_unknown_leases() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        ledger.create_snapshot_lease(100, 200)?;
        let unknown = crate::SnapshotLeaseId::new([0x77; 16])?;
        let failure = crate::publish_snapshot_lease_marker_for_test(catalog, unknown, 0x91)
            .expect_err("test marker publication must reject an unknown lease");
        assert_eq!(
            failure.code(),
            crate::CatalogFailureCode::IntegrityCorruption
        );
        Ok(())
    })
}

#[cfg(feature = "test-support")]
#[test]
fn snapshot_lease_marker_test_support_rejects_zero_transaction_identity()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        ledger.resume_snapshot_lease_with_marker(lease.identity(), 101, 1, [0x91; 32])?;
        let failure = crate::publish_snapshot_lease_marker_for_test(catalog, lease.identity(), 0)
            .expect_err("test marker publication must reject a zero transaction identity");
        assert_eq!(failure.code(), crate::CatalogFailureCode::LimitExceeded);
        Ok(())
    })
}

#[cfg(feature = "test-support")]
#[test]
fn snapshot_lease_marker_test_support_rejects_malformed_repeat_field() -> Result<(), Box<dyn Error>>
{
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        publish_lease_rewrite(catalog, 0x92, |bytes| bytes.truncate(119))?;
        let failure =
            crate::publish_snapshot_lease_marker_for_test(catalog, lease.identity(), 0x93)
                .expect_err("test marker publication must reject a truncated repeat field");
        assert_eq!(
            failure.code(),
            crate::CatalogFailureCode::IntegrityCorruption
        );
        Ok(())
    })
}

#[cfg(feature = "test-support")]
#[test]
fn snapshot_lease_marker_test_support_rejects_repeat_overflow() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let lease = ledger.create_snapshot_lease(100, 200)?;
        ledger.resume_snapshot_lease_with_marker(lease.identity(), 101, 1, [0x91; 32])?;
        publish_lease_rewrite(catalog, 0x94, |bytes| {
            bytes[119..127].copy_from_slice(&u64::MAX.to_be_bytes());
        })?;
        let failure =
            crate::publish_snapshot_lease_marker_for_test(catalog, lease.identity(), 0x95)
                .expect_err("test marker publication must reject repeat overflow");
        assert_eq!(failure.code(), crate::CatalogFailureCode::LimitExceeded);
        Ok(())
    })
}

#[test]
fn malformed_snapshot_lease_catalog_records_fail_closed() -> Result<(), Box<dyn Error>> {
    for (transaction, rewrite) in [
        (0xd1, corrupt_lease_version as fn(&mut Vec<u8>)),
        (0xd2, |bytes: &mut Vec<u8>| bytes[42] = u8::MAX),
        (0xd3, truncate_lease_header),
        (0xd4, append_lease_trailing_byte),
        (0xd5, |bytes: &mut Vec<u8>| {
            bytes[103..111].copy_from_slice(&3_701_u64.to_be_bytes());
        }),
        (0xd7, |bytes: &mut Vec<u8>| {
            bytes[103..111].copy_from_slice(&100_u64.to_be_bytes());
        }),
    ] {
        with_fixture(|authority, catalog, scope| {
            let ledger = ActiveSegmentLedger::open(
                authority,
                catalog,
                scope,
                SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
            )?;
            let identity = ledger.create_snapshot_lease(100, 200)?.identity();
            publish_lease_rewrite(catalog, transaction, rewrite)?;
            assert_eq!(
                ledger
                    .resume_snapshot_lease(identity, 101)
                    .expect_err("malformed durable lease must fail closed")
                    .code(),
                LedgerFailureCode::IntegrityCorruption
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn active_legacy_lease_with_unprovable_remaining_ttl_fails_closed() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xd6, |bytes| rewrite_v2_lease_as_v1(bytes, 3_702))?;
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 101)
                .expect_err("legacy active lease exceeds the one-hour remaining bound")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
        Ok(())
    })
}

#[test]
fn bounded_active_legacy_lease_is_normalized_when_resumed() -> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xd8, |bytes| rewrite_v2_lease_as_v1(bytes, 200))?;

        assert_eq!(
            ledger.resume_snapshot_lease(identity, 101)?.identity(),
            identity
        );
        let normalized_snapshot = catalog.pin()?;
        let normalized = normalized_snapshot
            .plaintext_objects()
            .find(|bytes| bytes.starts_with(b"PSLEASE1"))
            .ok_or("normalized snapshot lease missing")?;
        assert_eq!(normalized.get(8..10), Some(2_u16.to_be_bytes().as_slice()));
        assert_eq!(
            normalized.get(95..103),
            Some(101_u64.to_be_bytes().as_slice())
        );
        Ok(())
    })
}

fn publish_lease_rewrite(
    catalog: &Catalog<'_>,
    transaction: u8,
    rewrite: fn(&mut Vec<u8>),
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut found = false;
    let objects = basis
        .plaintext_objects()
        .map(|bytes| {
            let mut bytes = bytes.to_vec();
            if bytes.starts_with(b"PSLEASE1") {
                rewrite(&mut bytes);
                found = true;
            }
            CatalogObject::new(bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(found, "snapshot lease catalog record missing");
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::new(1)?,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn corrupt_lease_version(bytes: &mut Vec<u8>) {
    bytes.splice(8..10, 3_u16.to_be_bytes());
}

fn truncate_lease_header(bytes: &mut Vec<u8>) {
    bytes.truncate(9);
}

fn append_lease_trailing_byte(bytes: &mut Vec<u8>) {
    bytes.push(0);
}

fn rewrite_v2_lease_as_v1(bytes: &mut Vec<u8>, expiry: u64) {
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes.drain(95..103);
    bytes[95..103].copy_from_slice(&expiry.to_be_bytes());
}

fn lease_clock(seconds: i64) -> crate::LifecycleClock<crate::FixedLifecycleClockSource> {
    crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(
        positron_domain::time::UnixNanoseconds::new(seconds * 1_000_000_000),
    ))
}
