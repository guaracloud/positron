use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation,
    StoreBlockIdentity,
};
use positron_signals::{ScanCancellation, SchemaBudget, SchemaCheckpointFrontier};

use super::SchemaBuildObserver;
use super::{MAX_REPLAY_SHARDS, SchemaSessionFailure, SessionState, TenantSchemaSession};

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

impl TenantSchemaSession {
    pub fn replay_snapshot(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        governor: ResourceGovernor<'_>,
    ) -> Result<(), SchemaSessionFailure> {
        self.replay_snapshot_cancellable(tenant, snapshot, governor, &NeverCancelled)
    }

    pub fn replay_snapshot_cancellable(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        governor: ResourceGovernor<'_>,
        cancellation: &dyn ScanCancellation,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if tenant != state.tenant || snapshot.scope().tenant_id() != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        if !state.catalog.governed_by(governor) {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        let frontier = state
            .frontiers
            .iter()
            .find(|frontier| frontier.shard() == snapshot.scope().shard_id())
            .copied();
        verify_frontier(snapshot, frontier)?;
        for block in snapshot
            .blocks()
            .iter()
            .filter(|block| frontier.is_none_or(|known| block.position() > known.position()))
        {
            let digest = block
                .content_digest()
                .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
            let decode_capacity =
                reserve_replay_decode_capacity(tenant, block.payload().len(), governor)?;
            let observer = SchemaBuildObserver::new_scan(
                decode_capacity
                    .granted()
                    .get(ResourceDimension::CpuWorkUnits),
                cancellation,
            );
            let delta = state
                .catalog
                .replay_observed_cancellable(tenant, snapshot, block, cancellation, &observer)
                .map_err(map_replay_observed_failure)?;
            let retained_bytes = u64::try_from(delta.retained_memory_bytes())
                .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
            let next_retained = state
                .retained_charge_bytes
                .checked_add(retained_bytes)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
            let capacity = reserve_schema_memory(tenant, retained_bytes, governor)?;
            ensure_retained_slot(&state, capacity.is_some())?;
            ensure_frontier_slot(&state, snapshot.scope().shard_id())?;
            let frontier = validated_frontier(
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                digest,
            )?;
            state
                .catalog
                .reconcile_block_identity(block.identity(), digest)
                .map_err(SchemaSessionFailure::Schema)?;
            state
                .catalog
                .commit(delta, block.identity(), digest)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            drop(decode_capacity);
            if let Some(capacity) = capacity {
                state.retained_capacity.push(capacity.transfer());
            }
            state.retained_charge_bytes = next_retained;
            publish_frontier(&mut state, frontier);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn replay_snapshot_for_bootstrap(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        recovery: &mut ResourceReservation<'_>,
    ) -> Result<(), SchemaSessionFailure> {
        self.replay_snapshot_for_bootstrap_cancellable(tenant, snapshot, recovery, &NeverCancelled)
    }

    pub(crate) fn replay_snapshot_for_bootstrap_cancellable(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        recovery: &mut ResourceReservation<'_>,
        cancellation: &dyn ScanCancellation,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if tenant != state.tenant || snapshot.scope().tenant_id() != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        let frontier = state
            .frontiers
            .iter()
            .find(|frontier| frontier.shard() == snapshot.scope().shard_id())
            .copied();
        verify_frontier(snapshot, frontier)?;
        for block in snapshot
            .blocks()
            .iter()
            .filter(|block| frontier.is_none_or(|known| block.position() > known.position()))
        {
            let digest = block
                .content_digest()
                .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
            ensure_replay_capacity(recovery, block.payload().len())?;
            let observer = SchemaBuildObserver::new_scan(
                recovery.granted().get(ResourceDimension::CpuWorkUnits),
                cancellation,
            );
            let delta = state
                .catalog
                .replay_observed_cancellable(tenant, snapshot, block, cancellation, &observer)
                .map_err(map_replay_observed_failure)?;
            ensure_frontier_slot(&state, snapshot.scope().shard_id())?;
            let frontier = validated_frontier(
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                digest,
            )?;
            state
                .catalog
                .reconcile_block_identity(block.identity(), digest)
                .map_err(SchemaSessionFailure::Schema)?;
            state
                .catalog
                .commit(delta, block.identity(), digest)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            publish_frontier(&mut state, frontier);
        }
        Ok(())
    }
}

fn verify_frontier(
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
    Ok(())
}

fn reserve_replay_decode_capacity(
    tenant: TenantId,
    payload_bytes: usize,
    governor: ResourceGovernor<'_>,
) -> Result<ResourceReservation<'_>, SchemaSessionFailure> {
    let bytes = u64::try_from(
        SchemaBudget::replay_working_memory_bytes(payload_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
    )
    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    let cpu_work = SchemaBudget::replay_schema_work_units(payload_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    let amounts = ResourceAmounts::new([bytes, 0, 0, 0, 0, 0, 0, 0, cpu_work, 0, 0]);
    let claim =
        positron_kernel::WorkClaim::tenant(tenant, positron_kernel::WorkKind::Ingest, amounts)
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    governor
        .reserve(claim)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
}

fn map_replay_observed_failure(failure: positron_signals::LogStoreFailure) -> SchemaSessionFailure {
    match failure.code() {
        positron_signals::LogStoreFailureCode::BudgetExhausted
        | positron_signals::LogStoreFailureCode::ResourceExhausted
        | positron_signals::LogStoreFailureCode::ResourceAdmissionRefused => {
            SchemaSessionFailure::StateUnavailable
        },
        positron_signals::LogStoreFailureCode::Cancelled => SchemaSessionFailure::StateUnavailable,
        positron_signals::LogStoreFailureCode::InvalidInput
        | positron_signals::LogStoreFailureCode::LimitExceeded
        | positron_signals::LogStoreFailureCode::MalformedBlock
        | positron_signals::LogStoreFailureCode::PhysicalScopeMismatch
        | positron_signals::LogStoreFailureCode::Kernel
        | positron_signals::LogStoreFailureCode::ClockUnavailable
        | positron_signals::LogStoreFailureCode::Internal => SchemaSessionFailure::ReplayIntegrity,
    }
}

pub(super) fn reserve_query_index_capacity(
    tenant: TenantId,
    payload_bytes: usize,
    governor: ResourceGovernor<'_>,
) -> Result<ResourceReservation<'_>, SchemaSessionFailure> {
    reserve_replay_decode_capacity(tenant, payload_bytes, governor)
}

fn ensure_replay_capacity(
    capacity: &ResourceReservation<'_>,
    payload_bytes: usize,
) -> Result<(), SchemaSessionFailure> {
    let required = u64::try_from(
        SchemaBudget::replay_working_memory_bytes(payload_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
    )
    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    if capacity.granted().get(ResourceDimension::MemoryBytes) < required {
        return Err(SchemaSessionFailure::StateUnavailable);
    }
    Ok(())
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
    if state
        .frontiers
        .iter()
        .any(|frontier| frontier.shard() == shard)
    {
        return Ok(());
    }
    if state.frontiers.len() >= MAX_REPLAY_SHARDS {
        return Err(SchemaSessionFailure::ReplayLimitExceeded);
    }
    Ok(())
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
    if let Some(known) = state
        .frontiers
        .iter_mut()
        .find(|known| known.shard() == frontier.shard())
    {
        *known = frontier;
        return;
    }
    state.frontiers.push(frontier);
    state.frontiers.sort_by_key(|known| known.shard());
}

pub(super) fn reserve_schema_memory<'authority>(
    tenant: TenantId,
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
