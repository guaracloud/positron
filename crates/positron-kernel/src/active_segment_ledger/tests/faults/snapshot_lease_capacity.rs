use super::*;
use crate::active_segment_ledger::fault::{LedgerFileEvent, with_ledger_fault};
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

fn assert_same_resources(before: crate::ResourceSnapshot, after: crate::ResourceSnapshot) {
    assert_eq!(after.outstanding_total(), before.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), before.usage(dimension));
    }
}

fn fixed_lease_clock(seconds: i64) -> crate::LifecycleClock<crate::FixedLifecycleClockSource> {
    crate::LifecycleClock::new(crate::FixedLifecycleClockSource::new(
        positron_domain::time::UnixNanoseconds::new(seconds * 1_000_000_000),
    ))
}

#[test]
fn marker_resize_refusal_keeps_the_lease_retryable_after_capacity_returns()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;

        for now in 100..165 {
            let baseline = authority.governor().inspect()?;
            let lease = ledger.create_snapshot_lease(now, now + 100)?;
            let identity = lease.identity();
            drop(lease);
            let blocker = resize_blocker(authority, scope.tenant)?;
            let blocked = authority.governor().inspect()?;

            let refusal = ledger
                .resume_snapshot_lease_with_marker(identity, now + 1, 1, [9; 32])
                .expect_err("metadata growth must refuse while capacity is saturated");
            assert_eq!(refusal.code(), LedgerFailureCode::ResourceAdmissionRefused);
            assert_eq!(
                ledger.snapshot_lease_usage(identity, now + 1)?,
                SnapshotLeaseUsage::default()
            );
            assert_same_resources(blocked, authority.governor().inspect()?);

            drop(blocker);
            let resumed =
                ledger.resume_snapshot_lease_with_marker(identity, now + 1, 1, [9; 32])?;
            assert_eq!(resumed.resume_count(), 1);
            drop(resumed);
            ledger.release_snapshot_lease(identity)?;
            assert_same_resources(baseline, authority.governor().inspect()?);
        }
        Ok(())
    })
}

#[test]
fn usage_resize_refusal_keeps_the_lease_retryable_after_capacity_returns()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let delta = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 7);

        for now in 100..165 {
            let baseline = authority.governor().inspect()?;
            let lease = ledger.create_snapshot_lease(now, now + 100)?;
            let identity = lease.identity();
            drop(lease);
            let blocker = resize_blocker(authority, scope.tenant)?;
            let blocked = authority.governor().inspect()?;

            let refusal = ledger
                .record_snapshot_lease_usage(identity, delta)
                .expect_err("usage metadata growth must refuse while capacity is saturated");
            assert_eq!(refusal.code(), LedgerFailureCode::ResourceAdmissionRefused);
            assert_eq!(
                ledger.snapshot_lease_usage(identity, now + 1)?,
                SnapshotLeaseUsage::default()
            );
            assert_same_resources(blocked, authority.governor().inspect()?);

            drop(blocker);
            assert_eq!(ledger.record_snapshot_lease_usage(identity, delta)?, delta);
            assert_eq!(ledger.snapshot_lease_usage(identity, now + 1)?, delta);
            ledger.release_snapshot_lease(identity)?;
            assert_same_resources(baseline, authority.governor().inspect()?);
        }
        Ok(())
    })
}

#[test]
fn ambiguous_lease_creation_is_owned_by_bounded_cleanup_before_retry() -> Result<(), Box<dyn Error>>
{
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let baseline = authority.governor().inspect()?;

        for now in 100..165 {
            let failure =
                with_ledger_fault(LedgerFileEvent::BeforeLeaseCreationReconciliation, || {
                    ledger.create_snapshot_lease(now, now + 100)
                })
                .expect_err("an unproven post-publication outcome must remain typed");
            assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::CommitAmbiguous
            );

            let replacement = ledger.create_snapshot_lease(now + 1, now + 101)?;
            let replacement_identity = replacement.identity();
            drop(replacement);
            ledger.release_snapshot_lease(replacement_identity)?;
            assert_same_resources(baseline, authority.governor().inspect()?);
            assert_eq!(
                catalog
                    .pin()?
                    .plaintext_objects()
                    .filter(|bytes| bytes.starts_with(b"PSLEASE1"))
                    .count(),
                0
            );
        }

        drop(ledger);
        let reopened = ActiveSegmentLedger::open_with_clock(
            authority,
            catalog,
            scope,
            key(),
            &fixed_lease_clock(200),
        )?;
        assert_same_resources(baseline, authority.governor().inspect()?);
        drop(reopened);
        Ok(())
    })
}

#[test]
fn definitive_lease_creation_failure_releases_prepublication_ownership()
-> Result<(), Box<dyn Error>> {
    with_fixture(|authority, catalog, scope| {
        let key = || SegmentProtectionKey::from_owned(Box::new([0x75; 32]));
        let ledger = ActiveSegmentLedger::open(authority, catalog, scope, key())?;
        let baseline = authority.governor().inspect()?;

        let failure = with_catalog_fault(CatalogFileEvent::WriteObject, || {
            ledger.create_snapshot_lease(100, 200)
        })
        .expect_err("a definitive publication failure must not retain a lease");
        assert_eq!(failure.code(), LedgerFailureCode::StorageUnavailable);
        assert_eq!(
            authority.governor().inspect()?.outstanding_total(),
            baseline.outstanding_total()
        );
        for dimension in ResourceDimension::ALL {
            assert_eq!(
                authority.governor().inspect()?.usage(dimension),
                baseline.usage(dimension),
                "definitive creation failure leaked {dimension:?}",
            );
        }
        assert_eq!(
            catalog
                .pin()?
                .plaintext_objects()
                .filter(|bytes| bytes.starts_with(b"PSLEASE1"))
                .count(),
            0
        );

        let retry = ledger.create_snapshot_lease(101, 201)?;
        let identity = retry.identity();
        drop(retry);
        ledger.release_snapshot_lease(identity)?;
        assert_eq!(
            authority.governor().inspect()?.outstanding_total(),
            baseline.outstanding_total()
        );
        Ok(())
    })
}
