use positron_domain::routing::VirtualShardId;
use positron_kernel::{
    ResourceAmounts, ResourceDimension, ResourceReservation, StoreBlockIdentity,
    TransferredResourceReservation,
};
use positron_signals::{SchemaDelta, SchemaFailure};

use crate::schema_session::{DurableSchemaOutcome, DurableSchemaResolution};
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

pub(super) struct RetentionResolution {
    pub(super) identity: StoreBlockIdentity,
    pub(super) shard: VirtualShardId,
    pub(super) staged: SchemaDelta,
    pub(super) capacity_bytes: u64,
    pub(super) digest: [u8; 32],
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
    governor: positron_kernel::ResourceGovernor<'_>,
) -> IngestOutcome {
    if schema
        .resolve_durable_outcome(
            DurableSchemaResolution {
                identity,
                shard,
                staged: delta,
                capacity: None,
                capacity_bytes: 0,
                outcome: DurableSchemaOutcome::DefiniteFailure,
            },
            governor,
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
    resolution: RetentionResolution,
    failure: SchemaCapacityRetentionFailure<'_>,
    governor: positron_kernel::ResourceGovernor<'_>,
) -> IngestOutcome {
    let RetentionResolution {
        identity,
        shard,
        staged,
        capacity_bytes,
        digest,
    } = resolution;
    let (capacity, outcome) = failure.into_parts();
    if schema
        .resolve_durable_outcome(
            DurableSchemaResolution {
                identity,
                shard,
                staged,
                capacity: Some(capacity.transfer()),
                capacity_bytes,
                outcome: DurableSchemaOutcome::Ambiguous { digest },
            },
            governor,
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
        | SchemaSessionFailure::Schema(SchemaFailure::Observed(_))
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
