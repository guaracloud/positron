use positron_governance::schema_checkpoint_audit_intent;
use positron_ingest::{SchemaBudget, TenantSchemaCheckpoint, load_schema_checkpoint};
use positron_kernel::{
    AuditIntent, Catalog, CatalogFailureCode, CatalogObject, CatalogProposal, CatalogSnapshot,
    FormatEpoch, ResourceAmounts, ResourceDimension, TransactionId, TransferredResourceReservation,
    WorkClaim, WorkKind,
};

use super::{ServiceFailure, failure::classify_catalog_failure_code};

const MAX_ATTEMPTS: u8 = 3;
pub(super) fn publish_quiescent_checkpoint(
    instance: &crate::InitializedInstance,
    checkpoint: TenantSchemaCheckpoint,
) -> Result<(), ServiceFailure> {
    if checkpoint.tenant() != instance.tenant {
        return Err(ServiceFailure::CorruptState);
    }
    let initial_memory = u64::try_from(
        SchemaBudget::release_1()
            .map_err(|_| ServiceFailure::Internal)?
            .max_persistent_bytes(),
    )
    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let capacity = reserve_capacity(instance, initial_memory)?;
    publish_with_capacity(instance, checkpoint, capacity.transfer())
}

pub(super) fn reserve_shutdown_capacity(
    instance: &crate::InitializedInstance,
) -> Result<TransferredResourceReservation, ServiceFailure> {
    let catalog = open_catalog(instance)?;
    let snapshot = catalog.pin().map_err(map_catalog)?;
    let current = load_schema_checkpoint(&snapshot, instance.tenant, instance.resource_governor())
        .map_err(|_| ServiceFailure::CorruptState)?;
    let maximum = SchemaBudget::release_1()
        .map_err(|_| ServiceFailure::Internal)?
        .max_persistent_bytes();
    let memory = replacement_memory(&snapshot, current.as_deref(), maximum)?;
    Ok(reserve_capacity(instance, memory)?.transfer())
}

pub(super) fn publish_with_capacity(
    instance: &crate::InitializedInstance,
    checkpoint: TenantSchemaCheckpoint,
    transferred: TransferredResourceReservation,
) -> Result<(), ServiceFailure> {
    let mut capacity = transferred
        .reclaim(instance.resource_governor())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let transaction = TransactionId::new(
        instance
            .key
            .random_identifier()
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|_| ServiceFailure::KeyUnavailable)?;
    let bytes = checkpoint.into_catalog_bytes();
    let audit = schema_checkpoint_audit_intent(instance.tenant, &bytes)
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    let catalog = open_catalog(instance)?;

    for _ in 0..MAX_ATTEMPTS {
        let snapshot = catalog.pin().map_err(map_catalog)?;
        let current =
            load_schema_checkpoint(&snapshot, instance.tenant, instance.resource_governor())
                .map_err(|failure| {
                    if failure.catalog_code().is_some() {
                        ServiceFailure::CatalogUnavailable
                    } else {
                        ServiceFailure::CorruptState
                    }
                })?;
        if current.as_deref() == Some(bytes.as_slice()) {
            return Ok(());
        }
        let memory = replacement_memory(&snapshot, current.as_deref(), bytes.len())?;
        let required = maintenance_amounts(memory);
        if ResourceDimension::ALL
            .iter()
            .any(|dimension| required.get(*dimension) > capacity.granted().get(*dimension))
        {
            capacity
                .try_resize(required)
                .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        }
        let proposal = replacement(&snapshot, current.as_deref(), &bytes, transaction)?;
        match catalog.commit(
            snapshot.identity(),
            proposal,
            Some(AuditIntent::new(audit.clone()).map_err(map_catalog)?),
        ) {
            Ok(_) => return Ok(()),
            Err(failure)
                if matches!(
                    failure.code(),
                    CatalogFailureCode::StaleGeneration | CatalogFailureCode::StorageUnavailable
                ) => {},
            Err(failure) => return Err(map_catalog(failure)),
        }
    }
    Err(ServiceFailure::CatalogUnavailable)
}

fn reserve_capacity<'a>(
    instance: &'a crate::InitializedInstance,
    memory: u64,
) -> Result<positron_kernel::ResourceReservation<'a>, ServiceFailure> {
    let claim = WorkClaim::tenant(
        instance.tenant,
        WorkKind::OrdinaryMaintenanceBackup,
        maintenance_amounts(memory),
    )
    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    instance
        .resource_governor()
        .reserve(claim)
        .map_err(|_| ServiceFailure::CapacityUnavailable)
}

fn open_catalog(instance: &crate::InitializedInstance) -> Result<Catalog<'_>, ServiceFailure> {
    Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(map_catalog)
}

fn replacement_memory(
    snapshot: &CatalogSnapshot,
    current: Option<&[u8]>,
    checkpoint_bytes: usize,
) -> Result<u64, ServiceFailure> {
    let object_count = snapshot
        .object_identities()
        .count()
        .checked_add(1)
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    let mut total = checkpoint_bytes
        .checked_add(
            object_count
                .checked_mul(std::mem::size_of::<CatalogObject>())
                .ok_or(ServiceFailure::CapacityUnavailable)?,
        )
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<CatalogObject>>()))
        .ok_or(ServiceFailure::CapacityUnavailable)?;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(ServiceFailure::CorruptState)?;
        if current != Some(bytes) {
            total = total
                .checked_add(bytes.len())
                .ok_or(ServiceFailure::CapacityUnavailable)?;
        }
    }
    u64::try_from(total).map_err(|_| ServiceFailure::CapacityUnavailable)
}

fn replacement(
    snapshot: &CatalogSnapshot,
    current: Option<&[u8]>,
    checkpoint: &[u8],
    transaction: TransactionId,
) -> Result<CatalogProposal, ServiceFailure> {
    let count = snapshot.object_identities().count();
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(count.saturating_add(1))
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    for identity in snapshot.object_identities() {
        let bytes = snapshot
            .object(identity)
            .map_err(map_catalog)?
            .ok_or(ServiceFailure::CorruptState)?;
        if current == Some(bytes) {
            continue;
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| ServiceFailure::CapacityUnavailable)?;
        retained.extend_from_slice(bytes);
        objects.push(CatalogObject::new(retained).map_err(map_catalog)?);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(checkpoint.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    encoded.extend_from_slice(checkpoint);
    objects.push(CatalogObject::new(encoded).map_err(map_catalog)?);
    CatalogProposal::new(transaction, FormatEpoch::CATALOG_V1, objects).map_err(map_catalog)
}

fn maintenance_amounts(memory: u64) -> ResourceAmounts {
    ResourceAmounts::new([memory, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0])
}

fn map_catalog(failure: positron_kernel::CatalogFailure) -> ServiceFailure {
    classify_catalog_failure_code(failure.code())
}

#[cfg(test)]
#[path = "tests/schema_maintenance_failures.rs"]
mod failure_tests;
