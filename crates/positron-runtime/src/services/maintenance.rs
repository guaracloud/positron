//! Runtime composition of the Catalog-backed maintenance coordinator.

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
