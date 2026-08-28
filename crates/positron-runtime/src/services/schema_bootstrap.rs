use positron_domain::routing::SignalKind;
use positron_ingest::{
    SchemaReplayBuilder, SchemaSessionFailure, TenantSchemaCheckpoint, TenantSchemaRegistry,
    load_schema_checkpoint,
};
use positron_kernel::{ActiveSegmentLedger, Catalog};

use super::{
    ServiceFailure, failure::classify_catalog_failure_code, failure::classify_ledger_failure_code,
};

pub(super) struct RecoveredSchema {
    pub(super) registry: TenantSchemaRegistry,
    pub(super) dirty_checkpoint: Option<TenantSchemaCheckpoint>,
}

pub(super) fn classify_replay_failure(failure: SchemaSessionFailure) -> ServiceFailure {
    match failure {
        SchemaSessionFailure::Cancelled => ServiceFailure::Cancelled,
        SchemaSessionFailure::StateUnavailable
        | SchemaSessionFailure::ReplayLimitExceeded
        | SchemaSessionFailure::RegistryLimitExceeded => ServiceFailure::CapacityUnavailable,
        SchemaSessionFailure::Schema(schema) => match schema {
            positron_signals::SchemaFailure::InvalidBudget
            | positron_signals::SchemaFailure::LimitExceeded
            | positron_signals::SchemaFailure::AllocationUnavailable
            | positron_signals::SchemaFailure::Observed(
                positron_signals::ScanObservationFailureCode::BudgetExhausted
                | positron_signals::ScanObservationFailureCode::DecodedRecordsExhausted
                | positron_signals::ScanObservationFailureCode::ResourceExhausted
                | positron_signals::ScanObservationFailureCode::Internal,
            ) => ServiceFailure::CapacityUnavailable,
            positron_signals::SchemaFailure::InvalidPath
            | positron_signals::SchemaFailure::PathTooLong
            | positron_signals::SchemaFailure::InvalidValue
            | positron_signals::SchemaFailure::MalformedCatalog => ServiceFailure::CorruptState,
            positron_signals::SchemaFailure::Observed(
                positron_signals::ScanObservationFailureCode::Cancelled,
            ) => ServiceFailure::Cancelled,
        },
        SchemaSessionFailure::TenantConflict
        | SchemaSessionFailure::InFlight
        | SchemaSessionFailure::PendingReconciliationRequired
        | SchemaSessionFailure::ReplayIntegrity => ServiceFailure::CorruptState,
    }
}

pub(super) fn recover(
    instance: &crate::InitializedInstance,
    cancellation: &crate::TaskCancellation,
) -> Result<RecoveredSchema, ServiceFailure> {
    let catalog = Catalog::open(
        &instance._authority,
        instance.instance,
        instance
            .key
            .catalog_secret(instance.instance)
            .map_err(|_| ServiceFailure::KeyUnavailable)?,
    )
    .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let basis = catalog
        .pin()
        .map_err(|failure| classify_catalog_failure_code(failure.code()))?;
    let checkpoint = load_schema_checkpoint(&basis, instance.tenant, instance.resource_governor())
        .map_err(|failure| {
            if failure.catalog_code().is_some() {
                ServiceFailure::CatalogUnavailable
            } else {
                ServiceFailure::CorruptState
            }
        })?;
    let mut replay = SchemaReplayBuilder::new(
        instance.tenant,
        checkpoint.as_deref(),
        instance._authority.recovery(),
    )
    .map_err(classify_replay_failure)?;
    let scopes = basis
        .reachable_ledger_scopes(instance.tenant, SignalKind::Logs)
        .map_err(|_| ServiceFailure::CorruptState)?;
    drop(basis);
    for scope in scopes {
        let protection = instance
            .key
            .segment_key(instance.instance, scope)
            .map_err(|_| ServiceFailure::KeyUnavailable)?;
        let ledger = ActiveSegmentLedger::open(&instance._authority, &catalog, scope, protection)
            .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
        // `replay` retains the admitted repair CPU/task reservation while the
        // immutable snapshot is constructed and replayed.
        let snapshot = ledger
            .snapshot()
            .map_err(|failure| classify_ledger_failure_code(failure.code()))?;
        replay
            .replay_snapshot_cancellable(&snapshot, cancellation)
            .map_err(classify_replay_failure)?;
        drop(snapshot);
        drop(ledger);
    }
    let current = replay
        .finish_cancellable(cancellation)
        .map_err(classify_replay_failure)?;
    let dirty = checkpoint
        .as_deref()
        .is_none_or(|persisted| persisted != current.catalog_bytes());
    if cancellation.is_cancelled() {
        return Err(ServiceFailure::Cancelled);
    }
    let registry = TenantSchemaRegistry::new(1).map_err(|_| ServiceFailure::Internal)?;
    registry
        .session_from_checkpoint(
            instance.tenant,
            current.catalog_bytes(),
            instance.resource_governor(),
        )
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    Ok(RecoveredSchema {
        registry,
        dirty_checkpoint: dirty.then_some(current),
    })
}
