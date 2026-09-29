//! Runtime composition of the Catalog-backed maintenance coordinator.

use std::time::Duration;

use positron_kernel::{
    ActiveSegmentLedger, Catalog, MaintenanceCoordinator, MaintenanceFailure, MaintenanceScope,
    MaintenanceTaskClass, SegmentScope, SnapshotLeaseId,
};

use super::{ServiceFailure, classify_catalog_failure_code};

pub(super) fn restore(instance: &crate::InitializedInstance) -> Result<(), ServiceFailure> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let restored = MaintenanceCoordinator::restore_from_catalog(&catalog).map_err(map_failure)?;
    drop(catalog);
    let mut coordinator = instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| ServiceFailure::Internal)?;
    *coordinator = restored;
    Ok(())
}

/// Performs one bounded coordinator dispatch for the only maintenance handler
/// installed by this runtime slice. Unsupported durable classes remain queued
/// for their own future handlers.
pub(super) fn wake_snapshot_lease_expiry(
    instance: &crate::InitializedInstance,
) -> Result<bool, ServiceFailure> {
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let coordinator = instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| ServiceFailure::Internal)?;
    let Some(execution) = coordinator
        .start_next_with_reservation_and_persist_for_class(
            &catalog,
            &instance._authority,
            now,
            instance.retention_time.status().state()
                == positron_kernel::LifecycleClockState::ClockUncertain,
            Some(MaintenanceTaskClass::SnapshotLeaseExpiry),
        )
        .map_err(map_failure)?
    else {
        return Ok(false);
    };
    let scope = scope_for_snapshot_lease_expiry(execution.task().scope(), instance.tenant)?;
    let identity = SnapshotLeaseId::new(execution.task().identity().to_bytes())
        .map_err(|_| ServiceFailure::Internal)?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let durable_identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let key = super::tenant_segment_key(instance, &durable_identity, scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        scope,
        key,
    )
    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
    ledger
        .complete_running_snapshot_lease_expiry_task(&coordinator, &execution, identity)
        .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
    Ok(true)
}

pub(super) fn run_snapshot_lease_expiry_worker(
    cancellation: &crate::TaskCancellation,
    mut wake: impl FnMut() -> Result<bool, ServiceFailure>,
) -> Result<(), ServiceFailure> {
    const IDLE_WAKE_INTERVAL: Duration = Duration::from_millis(20);
    const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(1);

    let mut retry_delay = IDLE_WAKE_INTERVAL;
    while !cancellation.is_cancelled() {
        match wake() {
            Ok(_) | Err(ServiceFailure::Cancelled) => retry_delay = IDLE_WAKE_INTERVAL,
            Err(
                ServiceFailure::CapacityUnavailable
                | ServiceFailure::CatalogUnavailable
                | ServiceFailure::StorageUnavailable,
            ) => {
                retry_delay = retry_delay.saturating_mul(2).min(MAX_TRANSIENT_BACKOFF);
            },
            Err(failure) => return Err(failure),
        }
        std::thread::sleep(retry_delay);
    }
    Ok(())
}

fn scope_for_snapshot_lease_expiry(
    scope: MaintenanceScope,
    expected_tenant: positron_domain::identity::TenantId,
) -> Result<SegmentScope, ServiceFailure> {
    match scope {
        MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } if tenant == expected_tenant => Ok(SegmentScope::new(tenant, signal, shard)),
        MaintenanceScope::System
        | MaintenanceScope::Tenant(_)
        | MaintenanceScope::Segment { .. } => Err(ServiceFailure::CorruptState),
    }
}

fn map_failure(failure: MaintenanceFailure) -> ServiceFailure {
    match failure {
        MaintenanceFailure::CatalogUnavailable => ServiceFailure::CatalogUnavailable,
        MaintenanceFailure::ResourceAdmissionRefused | MaintenanceFailure::CapacityExceeded => {
            ServiceFailure::CapacityUnavailable
        },
        MaintenanceFailure::InvalidInput
        | MaintenanceFailure::ConcurrentAccess
        | MaintenanceFailure::UnknownTask
        | MaintenanceFailure::InvalidTransition
        | MaintenanceFailure::PreconditionFailed
        | MaintenanceFailure::Paused => ServiceFailure::Internal,
    }
}
