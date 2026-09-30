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

    pub(super) fn generation(&self) -> u64 {
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

const INSTALLED_TASK_CLASSES: &[MaintenanceTaskClass] = &[
    MaintenanceTaskClass::SnapshotLeaseExpiry,
    MaintenanceTaskClass::RetentionPublication,
    MaintenanceTaskClass::RetentionReclamation,
    MaintenanceTaskClass::CatalogReclamation,
    MaintenanceTaskClass::GovernanceAuditCheckpoint,
];

/// Performs one bounded coordinator dispatch for the runtime's installed
/// maintenance handlers. Unsupported durable classes remain queued for their
/// own future handlers.
#[cfg(test)]
pub(super) fn wake_runtime_maintenance(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    let execution = match start_installed_maintenance(services, cancellation)? {
        Some(execution) => execution,
        None => {
            let discovered = discover_retention_publications(services, cancellation)?;
            let Some(execution) = start_installed_maintenance(services, cancellation)? else {
                return Ok(discovered);
            };
            execution
        },
    };
    complete_installed_maintenance(services, cancellation, &execution)
}

enum InstalledMaintenanceExecution<'authority> {
    GovernanceAuditCheckpoint {
        execution: MaintenanceExecution<'authority>,
    },
    SnapshotLeaseExpiry {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
        identity: SnapshotLeaseId,
    },
    RetentionPublication {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
    },
    RetentionReclamation {
        execution: MaintenanceExecution<'authority>,
        scope: SegmentScope,
    },
    CatalogReclamation {
        execution: MaintenanceExecution<'authority>,
    },
}

fn start_installed_maintenance<'authority>(
    services: &'authority super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<Option<InstalledMaintenanceExecution<'authority>>, ServiceFailure> {
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
    let selected = coordinator.start_next_with_reservation_and_persist_for_classes(
        &catalog,
        &instance._authority,
        now,
        instance.retention_time.status().state()
            == positron_kernel::LifecycleClockState::ClockUncertain,
        INSTALLED_TASK_CLASSES,
    );
    let Some(execution) = (match selected {
        Ok(execution) => execution,
        Err(failure) => return Err(map_failure(failure)),
    }) else {
        return Ok(None);
    };
    // The task is now durably Running. Drain cancellation remains effective
    // until the handler enters its atomic ledger-and-Catalog publication.
    // Restart recovery returns this bounded attempt to its durable queue.
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let execution = match execution.task().class() {
        MaintenanceTaskClass::GovernanceAuditCheckpoint => {
            InstalledMaintenanceExecution::GovernanceAuditCheckpoint { execution }
        },
        MaintenanceTaskClass::SnapshotLeaseExpiry => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            let identity = SnapshotLeaseId::new(execution.task().identity().to_bytes())
                .map_err(|_| ServiceFailure::Internal)?;
            InstalledMaintenanceExecution::SnapshotLeaseExpiry {
                execution,
                scope,
                identity,
            }
        },
        MaintenanceTaskClass::RetentionPublication => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            InstalledMaintenanceExecution::RetentionPublication { execution, scope }
        },
        MaintenanceTaskClass::RetentionReclamation => {
            let scope = scope_for_segment_task(execution.task().scope())?;
            InstalledMaintenanceExecution::RetentionReclamation { execution, scope }
        },
        MaintenanceTaskClass::CatalogReclamation => {
            if execution.task().scope() != MaintenanceScope::System {
                return Err(ServiceFailure::Internal);
            }
            InstalledMaintenanceExecution::CatalogReclamation { execution }
        },
        _ => return Err(ServiceFailure::Internal),
    };
    Ok(Some(execution))
}

fn complete_installed_maintenance(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
    execution: &InstalledMaintenanceExecution<'_>,
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
    if let InstalledMaintenanceExecution::GovernanceAuditCheckpoint { execution } = execution {
        services
            .instance
            .complete_governance_audit_checkpoint_execution(&catalog, execution)
            .map_err(|_| ServiceFailure::CatalogUnavailable)?;
        return Ok(true);
    }
    if let InstalledMaintenanceExecution::CatalogReclamation { execution } = execution {
        let coordinator = instance
            .maintenance_coordinator()
            .lock()
            .map_err(|_| ServiceFailure::Internal)?;
        catalog
            .complete_running_audit_retention_reclamation(&coordinator, execution)
            .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
        return Ok(true);
    }
    let coordinator = instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| ServiceFailure::Internal)?;
    let scope = match execution {
        InstalledMaintenanceExecution::SnapshotLeaseExpiry { scope, .. }
        | InstalledMaintenanceExecution::RetentionPublication { scope, .. }
        | InstalledMaintenanceExecution::RetentionReclamation { scope, .. } => *scope,
        InstalledMaintenanceExecution::GovernanceAuditCheckpoint { .. }
        | InstalledMaintenanceExecution::CatalogReclamation { .. } => {
            return Err(ServiceFailure::Internal);
        },
    };
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let durable_identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let key = super::tenant_segment_key(instance, &durable_identity, scope)?;
    let ledger = match execution {
        InstalledMaintenanceExecution::SnapshotLeaseExpiry { .. } => {
            ActiveSegmentLedger::open_with_retention_time(
                &instance._authority,
                &instance.retention_time,
                &catalog,
                scope,
                key,
            )
        },
        InstalledMaintenanceExecution::RetentionPublication { .. }
        | InstalledMaintenanceExecution::RetentionReclamation { .. } => {
            ActiveSegmentLedger::open_for_maintenance_with_retention_time(
                &instance._authority,
                &instance.retention_time,
                &catalog,
                scope,
                key,
            )
        },
        InstalledMaintenanceExecution::GovernanceAuditCheckpoint { .. } => {
            return Err(ServiceFailure::Internal);
        },
        InstalledMaintenanceExecution::CatalogReclamation { .. } => {
            return Err(ServiceFailure::Internal);
        },
    }
    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
    let completed = match execution {
        InstalledMaintenanceExecution::SnapshotLeaseExpiry {
            execution,
            identity,
            ..
        } => ledger.complete_running_snapshot_lease_expiry_task(&coordinator, execution, *identity),
        InstalledMaintenanceExecution::RetentionPublication { execution, .. } => ledger
            .complete_running_retention_publication_task(&coordinator, execution)
            .map(|_| ()),
        InstalledMaintenanceExecution::RetentionReclamation { execution, .. } => {
            ledger.complete_running_retention_reclamation_task(&coordinator, execution)
        },
        InstalledMaintenanceExecution::GovernanceAuditCheckpoint { .. } => {
            return Err(ServiceFailure::Internal);
        },
        InstalledMaintenanceExecution::CatalogReclamation { .. } => {
            return Err(ServiceFailure::Internal);
        },
    };
    if let Err(failure) = completed {
        return Err(super::classify_ledger_failure_code(failure.code()));
    }
    Ok(true)
}

fn discover_retention_publications(
    services: &super::ServiceHandle,
    cancellation: Option<&crate::TaskCancellation>,
) -> Result<bool, ServiceFailure> {
    if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
        return Err(ServiceFailure::Cancelled);
    }
    let instance = &services.instance;
    if instance.retention_time.status().state() != positron_kernel::LifecycleClockState::Certain {
        return Ok(false);
    }
    let Some(_catalog_operation) = services.try_catalog_operation()? else {
        return Err(ServiceFailure::CatalogUnavailable);
    };
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let snapshot = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let identity =
        positron_governance::Identity::open(&snapshot).map_err(|_| ServiceFailure::CorruptState)?;
    let tenants = positron_governance::TenantAdministration::registered_tenant_ids(&snapshot)
        .map_err(|_| ServiceFailure::CorruptState)?;
    let mut scopes = Vec::new();
    for tenant in tenants {
        for signal in [
            positron_domain::routing::SignalKind::Logs,
            positron_domain::routing::SignalKind::Traces,
        ] {
            let found = snapshot
                .reachable_ledger_scopes(tenant, signal)
                .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
            scopes
                .try_reserve(found.len())
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
            scopes.extend(found);
        }
    }
    drop(snapshot);
    let now = instance
        .retention_time
        .governance_now_seconds()
        .map_err(|_| ServiceFailure::StorageUnavailable)?;
    let coordinator = instance
        .maintenance_coordinator()
        .lock()
        .map_err(|_| ServiceFailure::Internal)?;
    let mut submitted = false;
    for scope in scopes {
        if cancellation.is_some_and(crate::TaskCancellation::is_cancelled) {
            return Err(ServiceFailure::Cancelled);
        }
        let maintenance_scope =
            MaintenanceScope::segment(scope.tenant_id(), scope.signal_kind(), scope.shard_id());
        if coordinator
            .has_nonterminal_retention_task_for_scope(maintenance_scope)
            .map_err(map_failure)?
        {
            continue;
        }
        let key = super::tenant_segment_key(instance, &identity, scope)?;
        let ledger = ActiveSegmentLedger::open_for_maintenance_with_retention_time(
            &instance._authority,
            &instance.retention_time,
            &catalog,
            scope,
            key,
        )
        .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
        match ledger.prepare_retention_publication() {
            Ok(preparation) => {
                preparation
                    .submit_and_persist(&coordinator, &catalog, now)
                    .map_err(|failure| super::classify_ledger_failure_code(failure.code()))?;
                submitted = true;
            },
            Err(failure)
                if matches!(
                    failure.code(),
                    positron_kernel::LedgerFailureCode::InvalidInput
                        | positron_kernel::LedgerFailureCode::ClockUncertain
                ) => {},
            Err(failure) => return Err(super::classify_ledger_failure_code(failure.code())),
        }
    }
    Ok(submitted)
}

pub(super) fn run_runtime_maintenance_worker(
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
                complete_installed_maintenance(services, Some(cancellation), execution)
            },
            None => match start_installed_maintenance(services, Some(cancellation)) {
                Ok(Some(execution)) => {
                    in_flight = Some(execution);
                    continue;
                },
                Ok(None) => match discover_retention_publications(services, Some(cancellation)) {
                    Ok(discovered) => {
                        match start_installed_maintenance(services, Some(cancellation)) {
                            Ok(Some(execution)) => {
                                in_flight = Some(execution);
                                continue;
                            },
                            Ok(None) => Ok(discovered),
                            Err(ServiceFailure::Cancelled) => break,
                            Err(failure) => Err(failure),
                        }
                    },
                    Err(ServiceFailure::Cancelled) => break,
                    Err(failure) => Err(failure),
                },
                Err(ServiceFailure::Cancelled) => break,
                Err(failure) => Err(failure),
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

fn scope_for_segment_task(scope: MaintenanceScope) -> Result<SegmentScope, ServiceFailure> {
    match scope {
        MaintenanceScope::Segment {
            tenant,
            signal,
            shard,
        } => Ok(SegmentScope::new(tenant, signal, shard)),
        MaintenanceScope::System | MaintenanceScope::Tenant(_) => Err(ServiceFailure::CorruptState),
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
