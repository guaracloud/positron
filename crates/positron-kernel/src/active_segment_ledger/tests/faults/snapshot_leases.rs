use std::collections::BTreeSet;

use super::super::super::snapshot_lease::publication_visible;
use super::*;
use crate::{
    OrdinaryPool, ResourceAmounts, ResourceDimension, SnapshotLeaseUsage, WorkClaim, WorkKind,
};

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
fn publication_reconciliation_rejects_malformed_durable_lease_objects() -> Result<(), Box<dyn Error>>
{
    with_fixture(|authority, catalog, scope| {
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0x75; 32])),
        )?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        publish_lease_rewrite(catalog, 0xe3, append_lease_trailing_byte)?;
        let snapshot = catalog.pin()?;
        assert!(!publication_visible(
            &snapshot,
            &BTreeSet::from([identity]),
            &[],
        ));
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
            ledger.resume_snapshot_lease_with_marker(identity, now, 1, [now as u8; 32])?;
            assert_eq!(ledger.snapshot_lease_marker_count_for_test(), 1);
            if now < 160 {
                let next = ledger.create_snapshot_lease(now + 1, now + 2)?.identity();
                assert_ne!(next, identity);
                assert_eq!(ledger.snapshot_lease_marker_count_for_test(), 0);
                ledger.release_snapshot_lease(next)?;
            }
        }

        let expired = ledger
            .resume_snapshot_lease(crate::SnapshotLeaseId::new([0x01; 16])?, 161)
            .expect_err("the synthetic identity is not a durable lease");
        assert_eq!(expired.code(), LedgerFailureCode::SnapshotExpired);
        assert_eq!(ledger.snapshot_lease_marker_count_for_test(), 0);
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
        let second = ledger.resume_snapshot_lease_with_marker(identity, 102, 1, [9; 32])?;
        assert_eq!(second.resume_count(), 2);
        assert_eq!(second.repeated_batch_count(), 1);
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
        let mut state = ledger.state.lock().map_err(|_| "ledger state")?;
        state
            .lease_resume_markers
            .get_mut(&identity)
            .ok_or("resume marker")?
            .usage = SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0);
        drop(state);
        assert_eq!(
            ledger
                .resume_snapshot_lease_with_marker(identity, 104, 2, [9; 32])
                .expect_err("inconsistent durable and cached usage must fail closed")
                .code(),
            LedgerFailureCode::IntegrityCorruption
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
fn ambiguous_usage_reconciliation_preserves_new_old_and_unknown_truth() -> Result<(), Box<dyn Error>>
{
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let identity = ledger.create_snapshot_lease(100, 200)?.identity();
        let basis = catalog.pin()?;
        let previous = super::super::super::snapshot_lease::records(&basis)?
            .into_iter()
            .find(|record| record.identity == identity)
            .ok_or("lease record")?;
        let mut expected = previous.clone();
        expected.usage = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7);
        let expected_encoded = super::super::super::snapshot_lease_codec::encode(&expected)?;

        let mut state = ledger.state.lock().map_err(|_| "ledger state")?;
        let previous_amounts = state
            .lease_reservations
            .get(&identity)
            .ok_or("lease reservation")?
            .granted();
        let old = ledger
            .reconcile_ambiguous_usage(
                &mut state,
                identity,
                &previous,
                &expected,
                &expected_encoded,
                previous_amounts,
            )
            .expect_err("old durable usage must remain retryable");
        assert_eq!(old.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            old.completion_state(),
            crate::LedgerCompletionState::CommitAmbiguous
        );

        let usage = SnapshotLeaseUsage::new(3, 0, 0, 0, 0, 0, 0);
        drop(state);
        ledger.record_snapshot_lease_usage(identity, usage)?;
        let basis = catalog.pin()?;
        let applied = super::super::super::snapshot_lease::records(&basis)?
            .into_iter()
            .find(|record| record.identity == identity)
            .ok_or("updated lease record")?;
        let expected_encoded = super::super::super::snapshot_lease_codec::encode(&applied)?;
        let mut state = ledger.state.lock().map_err(|_| "ledger state")?;
        let result = ledger.reconcile_ambiguous_usage(
            &mut state,
            identity,
            &previous,
            &applied,
            &expected_encoded,
            previous_amounts,
        )?;
        assert_eq!(result, applied.usage);

        let mut tampered_encoding = expected_encoded.clone();
        let first = tampered_encoding
            .first_mut()
            .ok_or("encoded lease record")?;
        *first ^= 1;
        let tampered = ledger
            .reconcile_ambiguous_usage(
                &mut state,
                identity,
                &previous,
                &applied,
                &tampered_encoding,
                previous_amounts,
            )
            .expect_err("matching usage with a mismatched authenticated encoding is ambiguous");
        assert_eq!(tampered.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            tampered.completion_state(),
            crate::LedgerCompletionState::CommitAmbiguous
        );

        let unknown_identity = crate::SnapshotLeaseId::new([0x77; 16])?;
        let unknown = ledger
            .reconcile_ambiguous_usage(
                &mut state,
                unknown_identity,
                &previous,
                &expected,
                &expected_encoded,
                previous_amounts,
            )
            .expect_err("an unverifiable durable outcome must remain ambiguous");
        assert_eq!(unknown.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            unknown.completion_state(),
            crate::LedgerCompletionState::CommitAmbiguous
        );
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
