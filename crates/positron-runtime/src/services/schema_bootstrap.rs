use positron_domain::routing::SignalKind;
use positron_ingest::{
    SchemaReplayBuilder, TenantSchemaCheckpoint, TenantSchemaRegistry, load_schema_checkpoint,
};
use positron_kernel::{ActiveSegmentLedger, Catalog};

use super::ServiceFailure;

pub(super) struct RecoveredSchema {
    pub(super) registry: TenantSchemaRegistry,
    pub(super) dirty_checkpoint: Option<TenantSchemaCheckpoint>,
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
    .map_err(|_| ServiceFailure::CatalogUnavailable)?;
    let basis = catalog
        .pin()
        .map_err(|_| ServiceFailure::CatalogUnavailable)?;
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
    .map_err(|_| ServiceFailure::CorruptState)?;
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
            .map_err(|failure| match failure.code() {
            positron_kernel::LedgerFailureCode::ResourceAdmissionRefused
            | positron_kernel::LedgerFailureCode::LimitExceeded => {
                ServiceFailure::CapacityUnavailable
            },
            _ => ServiceFailure::LedgerUnavailable,
        })?;
        // `replay` retains the admitted repair CPU/task reservation while the
        // immutable snapshot is constructed and replayed.
        let snapshot = ledger
            .snapshot()
            .map_err(|_| ServiceFailure::LedgerUnavailable)?;
        replay
            .replay_snapshot_cancellable(&snapshot, cancellation)
            .map_err(|failure| match failure {
                positron_ingest::SchemaSessionFailure::ReplayIntegrity
                | positron_ingest::SchemaSessionFailure::TenantConflict
                | positron_ingest::SchemaSessionFailure::Schema(_) => ServiceFailure::CorruptState,
                _ => ServiceFailure::Internal,
            })?;
        drop(snapshot);
        drop(ledger);
    }
    let current = replay.finish().map_err(|_| ServiceFailure::CorruptState)?;
    let dirty = checkpoint
        .as_deref()
        .is_none_or(|persisted| persisted != current.catalog_bytes());
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
