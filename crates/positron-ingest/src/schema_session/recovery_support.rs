use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation,
    StoreBlockIdentity,
};
use positron_signals::{ScanObservationFailureCode, SchemaCheckpointFrontier};

use super::replay_capacity::reserve_replay_decode_capacity;
use super::{MAX_REPLAY_SHARDS, SchemaBuildObserver, SchemaSessionFailure, SessionState};

pub(super) fn map_observation_failure(failure: ScanObservationFailureCode) -> SchemaSessionFailure {
    match failure {
        ScanObservationFailureCode::Cancelled => SchemaSessionFailure::Cancelled,
        ScanObservationFailureCode::BudgetExhausted
        | ScanObservationFailureCode::DecodedRecordsExhausted
        | ScanObservationFailureCode::ResourceExhausted
        | ScanObservationFailureCode::Internal => SchemaSessionFailure::StateUnavailable,
    }
}

pub(super) fn verify_frontier(
    snapshot: &LedgerSnapshot<'_>,
    frontier: Option<SchemaCheckpointFrontier>,
) -> Result<(), SchemaSessionFailure> {
    let Some(frontier) = frontier else {
        return Ok(());
    };
    let committed = snapshot
        .blocks()
        .iter()
        .find(|block| block.position() == frontier.position())
        .ok_or(SchemaSessionFailure::ReplayIntegrity)?;
    if committed.identity() != frontier.identity()
        || committed
            .content_digest()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?
            != frontier.digest()
    {
        return Err(SchemaSessionFailure::ReplayIntegrity);
    }
    Ok(())
}

pub(super) fn reconcile_pending(
    state: &mut SessionState,
    snapshot: &LedgerSnapshot<'_>,
    governor: ResourceGovernor<'_>,
) -> Result<(), SchemaSessionFailure> {
    let Some(pending) = state.pending.as_ref() else {
        return Ok(());
    };
    let identity = pending.identity;
    let shard = pending.shard;
    let digest = pending.digest;
    if snapshot.scope().shard_id() != shard {
        return Err(SchemaSessionFailure::PendingReconciliationRequired);
    }
    let Some(block) = snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == identity)
    else {
        return Err(SchemaSessionFailure::PendingReconciliationRequired);
    };
    if block
        .content_digest()
        .map_err(|_| SchemaSessionFailure::StateUnavailable)?
        != digest
    {
        return Err(SchemaSessionFailure::ReplayIntegrity);
    }
    if pending
        .capacity
        .as_ref()
        .is_some_and(|capacity| !capacity.can_reclaim_with(governor))
    {
        return Err(SchemaSessionFailure::StateUnavailable);
    }
    let decode_capacity =
        reserve_replay_decode_capacity(state.tenant, block.payload().len(), governor)?;
    let observer = SchemaBuildObserver::new(
        decode_capacity
            .granted()
            .get(ResourceDimension::CpuWorkUnits),
        None,
    );
    let replayed = state
        .catalog
        .replay_observed(state.tenant, snapshot, block, &observer)
        .map_err(map_replay_observed_failure)?;
    let retained_bytes = u64::try_from(replayed.retained_memory_bytes())
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    let next_retained = state
        .retained_charge_bytes
        .checked_add(retained_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    ensure_frontier_slot(state, shard)?;
    let frontier = validated_frontier(shard, block.position(), identity, digest)?;
    let retained_capacity = reserve_schema_memory(state.tenant, retained_bytes, governor)?;
    ensure_retained_slot(state, retained_capacity.is_some())?;
    state
        .catalog
        .commit(replayed, block.identity(), digest)
        .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
    drop(decode_capacity);
    publish_frontier(state, frontier);
    let pending = state
        .pending
        .take()
        .ok_or(SchemaSessionFailure::StateUnavailable)?;
    drop(pending);
    if let Some(capacity) = retained_capacity {
        state.retained_capacity.push(capacity.transfer());
    }
    state.retained_charge_bytes = next_retained;
    state.in_flight = None;
    state.checkpoint_changed = true;
    Ok(())
}

pub(super) fn map_replay_observed_failure(
    failure: positron_signals::LogStoreFailure,
) -> SchemaSessionFailure {
    classify_replay_failure_code(failure.code())
}

const fn classify_replay_failure_code(
    code: positron_signals::LogStoreFailureCode,
) -> SchemaSessionFailure {
    match code {
        positron_signals::LogStoreFailureCode::BudgetExhausted
        | positron_signals::LogStoreFailureCode::ResourceExhausted
        | positron_signals::LogStoreFailureCode::StorageExhausted
        | positron_signals::LogStoreFailureCode::StorageUnavailable
        | positron_signals::LogStoreFailureCode::ConcurrentWriter
        | positron_signals::LogStoreFailureCode::StaleGeneration
        | positron_signals::LogStoreFailureCode::ResourceAdmissionRefused => {
            SchemaSessionFailure::StateUnavailable
        },
        positron_signals::LogStoreFailureCode::Cancelled => SchemaSessionFailure::Cancelled,
        positron_signals::LogStoreFailureCode::InvalidInput
        | positron_signals::LogStoreFailureCode::LimitExceeded
        | positron_signals::LogStoreFailureCode::MalformedBlock
        | positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
        | positron_signals::LogStoreFailureCode::IntegrityCorruption
        | positron_signals::LogStoreFailureCode::AuthenticationFailed
        | positron_signals::LogStoreFailureCode::UnsupportedFormat
        | positron_signals::LogStoreFailureCode::IdempotencyConflict
        | positron_signals::LogStoreFailureCode::RecoveryRequired
        | positron_signals::LogStoreFailureCode::SnapshotExpired
        | positron_signals::LogStoreFailureCode::StaleResumeMarker
        | positron_signals::LogStoreFailureCode::ClockUnavailable
        | positron_signals::LogStoreFailureCode::Internal => SchemaSessionFailure::ReplayIntegrity,
    }
}

fn ensure_retained_slot(state: &SessionState, adding: bool) -> Result<(), SchemaSessionFailure> {
    if adding && state.retained_capacity.len() == state.retained_capacity.capacity() {
        Err(SchemaSessionFailure::ReplayLimitExceeded)
    } else {
        Ok(())
    }
}

pub(super) fn ensure_frontier_slot(
    state: &SessionState,
    shard: VirtualShardId,
) -> Result<(), SchemaSessionFailure> {
    ensure_frontier_slot_values(&state.frontiers, shard)
}

pub(super) fn ensure_frontier_slot_values(
    frontiers: &[SchemaCheckpointFrontier],
    shard: VirtualShardId,
) -> Result<(), SchemaSessionFailure> {
    if frontiers.iter().any(|frontier| frontier.shard() == shard)
        || frontiers.len() < MAX_REPLAY_SHARDS
    {
        Ok(())
    } else {
        Err(SchemaSessionFailure::ReplayLimitExceeded)
    }
}

pub(super) fn validated_frontier(
    shard: VirtualShardId,
    position: CommitPosition,
    identity: StoreBlockIdentity,
    digest: [u8; 32],
) -> Result<SchemaCheckpointFrontier, SchemaSessionFailure> {
    SchemaCheckpointFrontier::new(shard, position, identity, digest)
        .map_err(SchemaSessionFailure::Schema)
}

pub(super) fn publish_frontier(state: &mut SessionState, frontier: SchemaCheckpointFrontier) {
    publish_frontier_values(&mut state.frontiers, frontier);
}

pub(super) fn publish_frontier_values(
    frontiers: &mut Vec<SchemaCheckpointFrontier>,
    frontier: SchemaCheckpointFrontier,
) {
    if let Some(known) = frontiers
        .iter_mut()
        .find(|known| known.shard() == frontier.shard())
    {
        *known = frontier;
        return;
    }
    frontiers.push(frontier);
    frontiers.sort_by_key(|known| known.shard());
}

pub(super) fn reserve_schema_memory<'authority>(
    tenant: positron_domain::identity::TenantId,
    bytes: u64,
    governor: ResourceGovernor<'authority>,
) -> Result<Option<ResourceReservation<'authority>>, SchemaSessionFailure> {
    if bytes == 0 {
        return Ok(None);
    }
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    let claim =
        positron_kernel::WorkClaim::tenant(tenant, positron_kernel::WorkKind::Ingest, amounts)
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    governor
        .reserve(claim)
        .map(Some)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
}

#[cfg(test)]
mod failure_classification_tests {
    use super::{SchemaSessionFailure, classify_replay_failure_code, map_observation_failure};
    use positron_signals::{LogStoreFailureCode as Store, ScanObservationFailureCode as Observer};

    #[test]
    fn replay_observation_refusal_preserves_cancellation() {
        assert_eq!(
            map_observation_failure(Observer::Cancelled),
            SchemaSessionFailure::Cancelled
        );
        for failure in [
            Observer::BudgetExhausted,
            Observer::DecodedRecordsExhausted,
            Observer::ResourceExhausted,
            Observer::Internal,
        ] {
            assert_eq!(
                map_observation_failure(failure),
                SchemaSessionFailure::StateUnavailable
            );
        }
    }

    #[test]
    fn replay_preserves_retry_cancellation_and_integrity_classes() {
        for code in [
            Store::BudgetExhausted,
            Store::ResourceExhausted,
            Store::StorageExhausted,
            Store::StorageUnavailable,
            Store::ConcurrentWriter,
            Store::StaleGeneration,
            Store::ResourceAdmissionRefused,
        ] {
            assert_eq!(
                classify_replay_failure_code(code),
                SchemaSessionFailure::StateUnavailable
            );
        }
        assert_eq!(
            classify_replay_failure_code(Store::Cancelled),
            SchemaSessionFailure::Cancelled
        );
        for code in [
            Store::InvalidInput,
            Store::LimitExceeded,
            Store::MalformedBlock,
            Store::PhysicalScopeMismatch,
            Store::IntegrityCorruption,
            Store::AuthenticationFailed,
            Store::UnsupportedFormat,
            Store::IdempotencyConflict,
            Store::RecoveryRequired,
            Store::SnapshotExpired,
            Store::StaleResumeMarker,
            Store::ClockUnavailable,
            Store::Internal,
        ] {
            assert_eq!(
                classify_replay_failure_code(code),
                SchemaSessionFailure::ReplayIntegrity
            );
        }
    }
}
