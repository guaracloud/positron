//! Runtime composition of the Catalog-backed maintenance coordinator.

#[cfg(test)]
use positron_domain::routing::SignalKind;
#[cfg(test)]
use positron_kernel::{ActiveSegmentLedger, MaintenanceTaskClass, SegmentScope, SnapshotLeaseId};
use positron_kernel::{Catalog, MaintenanceCoordinator, MaintenanceFailure};

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

#[cfg(test)]
pub(super) fn run_snapshot_lease_expiry_once(
    instance: &crate::InitializedInstance,
) -> Result<bool, ServiceFailure> {
    let scope = SegmentScope::new(instance.tenant, SignalKind::Logs, instance.logs_shard);
    let now = instance
        .retention_time
        .governance_time_seconds(scope)
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
        .start_next_with_reservation_and_persist(&catalog, &instance._authority, now, false)
        .map_err(map_failure)?
    else {
        return Ok(false);
    };
    if execution.task().class() != MaintenanceTaskClass::SnapshotLeaseExpiry {
        return Err(ServiceFailure::Internal);
    }
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
