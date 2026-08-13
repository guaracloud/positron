use super::*;

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

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
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
        let reopened = ActiveSegmentLedger::open(authority, catalog, trace_scope, key())?;
        assert_eq!(
            reopened.resume_snapshot_lease(identity, 101)?.identity(),
            identity
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
fn snapshot_lease_pruning_is_restart_safe_atomic_and_rejects_time_regression()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let active = ledger.create_snapshot_lease(100, 1_000)?.identity();
        let _expired = ledger.create_snapshot_lease(101, 102)?;
        drop(ledger);

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let failure = with_catalog_fault(CatalogFileEvent::SynchronizeCommit, || {
            reopened.create_snapshot_lease(102, 200)
        })
        .expect_err("failed pruning cannot publish a partial lease set");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            reopened.resume_snapshot_lease(active, 102)?.identity(),
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

        let reopened = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let resumed = reopened.resume_snapshot_lease(identity, 101)?;
        assert_eq!(resumed.identity(), identity);
        assert_eq!(resumed.expiry(), 200);
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
