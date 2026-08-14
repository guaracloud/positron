use positron_domain::routing::VirtualShardId;
use positron_kernel::{
    ResourceAmounts, ResourceDimension, ResourceReservation, StoreBlockIdentity,
    TransferredResourceReservation,
};
use positron_signals::{SchemaDelta, SchemaFailure};

use crate::schema_session::DurableSchemaOutcome;
use crate::{SchemaSessionFailure, TenantSchemaSession};

use super::{IngestFailureCode, IngestOutcome};

pub(super) fn retain_schema_capacity(
    mut reservation: ResourceReservation<'_>,
    bytes: u64,
) -> Result<Option<TransferredResourceReservation>, IngestOutcome> {
    if bytes == 0 {
        drop(reservation);
        return Ok(None);
    }
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
        .map_err(|_| IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded))?;
    reservation
        .try_resize(amounts)
        .map_err(|_| IngestOutcome::Ambiguous(IngestFailureCode::CapacityUnavailable))?;
    Ok(Some(reservation.transfer()))
}

pub(super) fn rollback_schema(
    schema: &TenantSchemaSession,
    identity: StoreBlockIdentity,
    shard: VirtualShardId,
    delta: SchemaDelta,
    outcome: IngestOutcome,
) -> IngestOutcome {
    if schema
        .resolve_durable_outcome(
            identity,
            shard,
            delta,
            None,
            0,
            DurableSchemaOutcome::DefiniteFailure,
        )
        .is_err()
    {
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
    } else {
        outcome
    }
}

pub(super) fn map_schema_session_failure(failure: SchemaSessionFailure) -> IngestOutcome {
    match failure {
        SchemaSessionFailure::TenantConflict => {
            IngestOutcome::Permanent(IngestFailureCode::TenantConflict)
        },
        SchemaSessionFailure::Schema(
            SchemaFailure::InvalidBudget
            | SchemaFailure::InvalidPath
            | SchemaFailure::PathTooLong
            | SchemaFailure::InvalidValue
            | SchemaFailure::MalformedCatalog,
        ) => IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        SchemaSessionFailure::Schema(SchemaFailure::LimitExceeded)
        | SchemaSessionFailure::ReplayLimitExceeded
        | SchemaSessionFailure::RegistryLimitExceeded => {
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
        },
        SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable)
        | SchemaSessionFailure::StateUnavailable => {
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
        },
        SchemaSessionFailure::InFlight
        | SchemaSessionFailure::PendingReconciliationRequired
        | SchemaSessionFailure::ReplayIntegrity => {
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable)
        },
    }
}

#[cfg(test)]
#[path = "tests/schema_resolution.rs"]
mod tests;
