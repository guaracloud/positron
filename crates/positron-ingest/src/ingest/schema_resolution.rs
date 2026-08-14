use positron_domain::routing::VirtualShardId;
use positron_kernel::{
    ResourceAmounts, ResourceDimension, ResourceReservation, StoreBlockIdentity,
    TransferredResourceReservation,
};
use positron_signals::{SchemaDelta, SchemaFailure};

use crate::schema_session::DurableSchemaOutcome;
use crate::{SchemaSessionFailure, TenantSchemaSession};

use super::{IngestFailureCode, IngestOutcome};

pub(super) struct SchemaCapacityRetentionFailure<'authority> {
    reservation: ResourceReservation<'authority>,
    outcome: IngestOutcome,
}

pub(super) enum SchemaCapacityRetention<'authority> {
    Retained(Option<TransferredResourceReservation>),
    Failed(SchemaCapacityRetentionFailure<'authority>),
}

impl<'authority> SchemaCapacityRetentionFailure<'authority> {
    pub(super) fn into_parts(self) -> (ResourceReservation<'authority>, IngestOutcome) {
        (self.reservation, self.outcome)
    }
}

pub(super) fn retain_schema_capacity(
    mut reservation: ResourceReservation<'_>,
    bytes: u64,
) -> SchemaCapacityRetention<'_> {
    if bytes == 0 {
        drop(reservation);
        return SchemaCapacityRetention::Retained(None);
    }
    let amounts = match ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes) {
        Ok(amounts) => amounts,
        Err(_) => {
            return SchemaCapacityRetention::Failed(SchemaCapacityRetentionFailure {
                reservation,
                outcome: IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
            });
        },
    };
    if reservation.granted().get(ResourceDimension::MemoryBytes) < bytes
        || reservation.try_resize(amounts).is_err()
    {
        return SchemaCapacityRetention::Failed(SchemaCapacityRetentionFailure {
            reservation,
            outcome: IngestOutcome::Ambiguous(IngestFailureCode::CapacityUnavailable),
        });
    }
    SchemaCapacityRetention::Retained(Some(reservation.transfer()))
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

pub(super) fn resolve_after_retention_failure(
    schema: &TenantSchemaSession,
    identity: StoreBlockIdentity,
    shard: VirtualShardId,
    staged: SchemaDelta,
    capacity_bytes: u64,
    digest: [u8; 32],
    failure: SchemaCapacityRetentionFailure<'_>,
) -> IngestOutcome {
    let (capacity, outcome) = failure.into_parts();
    if schema
        .resolve_durable_outcome(
            identity,
            shard,
            staged,
            Some(capacity.transfer()),
            capacity_bytes,
            DurableSchemaOutcome::Ambiguous { digest },
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
