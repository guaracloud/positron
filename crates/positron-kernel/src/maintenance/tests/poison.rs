use std::panic::{AssertUnwindSafe, catch_unwind};

use super::{
    CatalogObject, MaintenanceCoordinator, MaintenanceFailure, MaintenanceScope, MaintenanceTaskId,
    SignalKind, TenantId, VirtualShardId,
};
use crate::SnapshotLeaseId;

#[test]
fn poisoned_prepublication_rollback_reports_concurrent_access_and_requires_recovery() {
    let coordinator = MaintenanceCoordinator::new();
    let tenant = TenantId::from_bytes([0x61; 16]).expect("tenant");
    let scope = MaintenanceScope::segment(
        tenant,
        SignalKind::Logs,
        VirtualShardId::new(1).expect("shard"),
    );
    let lease = SnapshotLeaseId::new([0x62; 16]).expect("lease");
    let submission = coordinator
        .prepare_snapshot_lease_expiry(
            lease,
            scope,
            CatalogObject::new(b"poisoned rollback lease binding".to_vec())
                .expect("catalog object")
                .identity(),
            1,
            2,
        )
        .expect("prepare the prepublication rollback");
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = coordinator.state.lock().expect("coordinator state");
        panic!("poison coordinator state after a prepared rollback");
    }));

    assert_eq!(
        submission.discard(&coordinator),
        Err(MaintenanceFailure::ConcurrentAccess),
        "a poisoned multi-step coordinator state cannot be recovered by a rollback path"
    );
    assert_eq!(
        coordinator
            .status(MaintenanceTaskId::new(lease.to_bytes()).expect("task identity"))
            .expect_err("the poisoned process cannot serve in-memory task state"),
        MaintenanceFailure::ConcurrentAccess
    );
}
