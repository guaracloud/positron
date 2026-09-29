//! Runtime composition of the Catalog-backed maintenance coordinator.

use std::{
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use positron_kernel::{
    ActiveSegmentLedger, Catalog, MaintenanceCoordinator, MaintenanceExecution, MaintenanceFailure,
    MaintenanceScope, MaintenanceTaskClass, SegmentScope, SnapshotLeaseId,
};

use super::{ServiceFailure, classify_catalog_failure_code};

#[derive(Clone)]
pub(super) struct MaintenanceWake {
    state: Arc<(Mutex<u64>, Condvar)>,
    idle_delay: Duration,
}

impl MaintenanceWake {
    pub(super) fn for_instance(instance: positron_kernel::InstanceId) -> Self {
        // The stable instance-specific offset prevents a fleet of otherwise
        // idle processes from reopening their catalogs on the same cadence.
        let offset = u64::from(instance.to_bytes()[0]) % 250;
        Self {
            state: Arc::new((Mutex::new(0), Condvar::new())),
            idle_delay: Duration::from_millis(500 + offset),
        }
    }

    pub(super) fn notify(&self) {
        let (generation, signal) = &*self.state;
        if let Ok(mut generation) = generation.lock() {
            *generation = generation.saturating_add(1);
            signal.notify_one();
        }
    }

    fn generation(&self) -> u64 {
        self.state.0.lock().map_or(0, |generation| *generation)
    }

    fn wait(&self, observed: &mut u64, delay: Duration) {
        let (generation, signal) = &*self.state;
        let Ok(current) = generation.lock() else {
            return;
        };
        if *current != *observed {
            *observed = *current;
            return;
        }
        if let Ok((current, _)) = signal.wait_timeout(current, delay) {
            *observed = *current;
        }
    }

    fn idle_delay(&self) -> Duration {
        self.idle_delay
    }
}

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
#[cfg(test)]
pub(super) fn wake_snapshot_lease_expiry(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let Some(execution) = start_snapshot_lease_expiry(services, cancellation)? else {
        return Ok(false);
    };
    complete_snapshot_lease_expiry(services, cancellation, &execution)
}

struct SnapshotLeaseExpiryExecution<'authority> {
    execution: MaintenanceExecution<'authority>,
    scope: SegmentScope,
    identity: SnapshotLeaseId,
}

fn start_snapshot_lease_expiry<'authority>(
    services: &'authority super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<Option<SnapshotLeaseExpiryExecution<'authority>>, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogUnavailable);
    };
    let instance = &services.instance;
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
        return Ok(None);
    };
    // The task is now durably Running. Drain cancellation remains effective
    // until the handler enters its atomic ledger-and-Catalog publication.
    // Restart recovery returns this bounded attempt to its durable queue.
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let scope = scope_for_snapshot_lease_expiry(execution.task().scope(), instance.tenant)?;
    let identity = SnapshotLeaseId::new(execution.task().identity().to_bytes())
        .map_err(|_| ServiceFailure::Internal)?;
    Ok(Some(SnapshotLeaseExpiryExecution {
        execution,
        scope,
        identity,
    }))
}

fn complete_snapshot_lease_expiry(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
    execution: &SnapshotLeaseExpiryExecution<'_>,
) -> Result<bool, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogUnavailable);
    };
    let instance = &services.instance;
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
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let durable_identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let key = super::tenant_segment_key(instance, &durable_identity, execution.scope)?;
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &instance._authority,
        &instance.retention_time,
        &catalog,
        execution.scope,
        key,
    )
    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
    ledger
        .complete_running_snapshot_lease_expiry_task(
            &coordinator,
            &execution.execution,
            execution.identity,
        )
        .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
    Ok(true)
}

pub(super) fn run_snapshot_lease_expiry_worker(
    services: &super::ServiceHandle,
    cancellation: &crate::TaskCancellation,
    wake_signal: &MaintenanceWake,
) -> Result<(), ServiceFailure> {
    const WORK_YIELD: Duration = Duration::from_millis(10);
    const INITIAL_TRANSIENT_BACKOFF: Duration = Duration::from_millis(50);
    const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(2);

    let mut observed = wake_signal.generation();
    let mut retry_delay = INITIAL_TRANSIENT_BACKOFF;
    let mut in_flight = None;
    while !cancellation.is_cancelled() {
        let result = match in_flight.as_ref() {
            Some(execution) => {
                complete_snapshot_lease_expiry(services, Some(cancellation), execution)
            },
            None => match start_snapshot_lease_expiry(services, Some(cancellation))? {
                Some(execution) => {
                    in_flight = Some(execution);
                    continue;
                },
                None => Ok(false),
            },
        };
        let delay = match result {
            Ok(true) => {
                in_flight = None;
                retry_delay = INITIAL_TRANSIENT_BACKOFF;
                WORK_YIELD
            },
            Ok(false) | Err(ServiceFailure::Cancelled) => {
                retry_delay = INITIAL_TRANSIENT_BACKOFF;
                wake_signal.idle_delay()
            },
            Err(
                ServiceFailure::CapacityUnavailable
                | ServiceFailure::CatalogUnavailable
                | ServiceFailure::StorageUnavailable,
            ) => {
                retry_delay = retry_delay.saturating_mul(2).min(MAX_TRANSIENT_BACKOFF);
                retry_delay
            },
            Err(failure) => return Err(failure),
        };
        wake_signal.wait(&mut observed, delay);
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
