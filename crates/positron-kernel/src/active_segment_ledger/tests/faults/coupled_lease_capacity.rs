use super::*;

#[test]
fn coupled_lease_creation_reclaims_one_terminal_expiry_descriptor_at_capacity()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x5e; 16])?,
        CatalogSecret::from_owned(Box::new([0x5f; 32]), Box::new([0x60; 32])),
    )?;
    let scope = SegmentScope::new(
        TenantId::from_bytes([0x64; 16])?,
        SignalKind::Logs,
        VirtualShardId::new(1)?,
    );
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x61; 32])),
    )?;
    let coordinator = MaintenanceCoordinator::new();
    let mut oldest = None;
    for now in 100..228 {
        let lease = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            now,
            std::num::NonZeroU64::new(1_000).ok_or("nonzero ttl")?,
            catalog.pin()?.identity(),
        )?;
        let identity = lease.identity();
        oldest.get_or_insert(identity);
        drop(lease);
        ledger.release_snapshot_lease_with_expiry_task(&coordinator, identity)?;
    }
    assert_eq!(
        coordinator
            .durable_records()
            .expect("terminal records")
            .len(),
        128
    );
    let oldest = oldest.ok_or("oldest lease")?;
    let refused = with_catalog_fault(CatalogFileEvent::WriteObject, || {
        ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
            &coordinator,
            228,
            std::num::NonZeroU64::new(1_000).expect("nonzero ttl"),
            catalog.pin().expect("catalog basis").identity(),
        )
    })
    .expect_err("a failed publication must not evict the selected terminal descriptor");
    assert_eq!(refused.code(), LedgerFailureCode::StorageUnavailable);
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new(oldest.to_bytes()).expect("task identity"))
            .expect("the failed proposal leaves the old terminal task in memory")
            .phase(),
        MaintenanceTaskPhase::Cancelled
    );
    let before_retry = catalog.pin()?;
    assert!(super::super::super::snapshot_lease::records(&before_retry)?.is_empty());
    assert_eq!(
        before_retry
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        128,
        "the failed proposal leaves the durable terminal inventory unchanged"
    );
    let replacement = ledger.create_snapshot_lease_for_at_catalog_with_expiry_task(
        &coordinator,
        228,
        std::num::NonZeroU64::new(1_000).ok_or("nonzero ttl")?,
        catalog.pin()?.identity(),
    )?;
    let replacement_identity = replacement.identity();
    drop(replacement);
    assert!(
        coordinator
            .status(MaintenanceTaskId::new(oldest.to_bytes()).expect("task identity"))
            .is_err(),
        "the oldest terminal descriptor makes space for the replacement pair"
    );
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new(replacement_identity.to_bytes()).expect("task identity"))
            .expect("replacement task")
            .phase(),
        MaintenanceTaskPhase::Queued
    );
    let snapshot = catalog.pin()?;
    assert_eq!(
        super::super::super::snapshot_lease::records(&snapshot)?.len(),
        1
    );
    assert_eq!(
        snapshot
            .plaintext_objects()
            .filter(|bytes| bytes.starts_with(b"PMTC"))
            .count(),
        128,
        "the proposal removes exactly one terminal descriptor while adding the new one"
    );
    Ok(())
}
