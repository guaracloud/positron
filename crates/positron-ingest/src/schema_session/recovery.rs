use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, StoreBlockIdentity,
    TransferredResourceReservation,
};
use positron_signals::{LogStore, SchemaCheckpointFrontier, SchemaFailure};

use super::{MAX_REPLAY_SHARDS, SchemaSessionFailure, SessionState, TenantSchemaSession};

impl TenantSchemaSession {
    pub fn replay_snapshot(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        governor: ResourceGovernor<'_>,
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
            let delta = LogStore::new()
                .replay_schema_block(tenant, snapshot, block, &state.catalog)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            let retained_bytes = u64::try_from(delta.retained_memory_bytes())
                .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
            let capacity = reserve_replay_capacity(tenant, retained_bytes, governor)?;
            LogStore::new()
                .apply_schema_delta(&mut state.catalog, delta)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            retain_capacity(&mut state, capacity, retained_bytes)?;
            set_frontier(
                &mut state,
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                block
                    .content_digest()
                    .map_err(|_| SchemaSessionFailure::StateUnavailable)?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn replay_snapshot_for_bootstrap(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
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
            let delta = LogStore::new()
                .replay_schema_block(tenant, snapshot, block, &state.catalog)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            LogStore::new()
                .apply_schema_delta(&mut state.catalog, delta)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            set_frontier(
                &mut state,
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                block
                    .content_digest()
                    .map_err(|_| SchemaSessionFailure::StateUnavailable)?,
            )?;
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
    let Some(pending) = state.pending.take() else {
        return Ok(());
    };
    if snapshot.scope().shard_id() != pending.shard {
        state.pending = Some(pending);
        return Err(SchemaSessionFailure::PendingReconciliationRequired);
    }
    let Some(block) = snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == pending.identity)
    else {
        return Ok(());
    };
    if block
        .content_digest()
        .map_err(|_| SchemaSessionFailure::StateUnavailable)?
        != pending.digest
    {
        return Err(SchemaSessionFailure::Schema(SchemaFailure::InvalidValue));
    }
    let replayed = LogStore::new()
        .replay_schema_block(state.tenant, snapshot, block, &state.catalog)
        .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
    let retained_bytes = u64::try_from(replayed.retained_memory_bytes())
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    drop(pending.delta);
    LogStore::new()
        .apply_schema_delta(&mut state.catalog, replayed)
        .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
    set_frontier(
        state,
        pending.shard,
        block.position(),
        pending.identity,
        pending.digest,
    )?;
    resize_pending_capacity(state, pending.capacity, retained_bytes, governor)
}

fn resize_pending_capacity(
    state: &mut SessionState,
    capacity: Option<TransferredResourceReservation>,
    retained_bytes: u64,
    governor: ResourceGovernor<'_>,
) -> Result<(), SchemaSessionFailure> {
    let Some(capacity) = capacity else {
        return if retained_bytes == 0 {
            Ok(())
        } else {
            Err(SchemaSessionFailure::StateUnavailable)
        };
    };
    if retained_bytes == 0 {
        capacity.release(governor);
        return Ok(());
    }
    let mut capacity = capacity
        .reclaim(governor)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
    capacity
        .try_resize(
            ResourceAmounts::only(ResourceDimension::MemoryBytes, retained_bytes)
                .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?,
        )
        .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
    retain_capacity(state, Some(capacity.transfer()), retained_bytes)
}

fn reserve_replay_capacity(
    tenant: TenantId,
    bytes: u64,
    governor: ResourceGovernor<'_>,
) -> Result<Option<TransferredResourceReservation>, SchemaSessionFailure> {
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
        .map(|capacity| Some(capacity.transfer()))
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
}

fn retain_capacity(
    state: &mut SessionState,
    capacity: Option<TransferredResourceReservation>,
    retained_bytes: u64,
) -> Result<(), SchemaSessionFailure> {
    if let Some(capacity) = capacity {
        state.retained_capacity.push(capacity);
    }
    state.retained_charge_bytes = state
        .retained_charge_bytes
        .checked_add(retained_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    Ok(())
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

pub(super) fn set_frontier(
    state: &mut SessionState,
    shard: VirtualShardId,
    position: CommitPosition,
    identity: StoreBlockIdentity,
    digest: [u8; 32],
) -> Result<(), SchemaSessionFailure> {
    let frontier = SchemaCheckpointFrontier::new(shard, position, identity, digest)
        .map_err(SchemaSessionFailure::Schema)?;
    if let Some(known) = state
        .frontiers
        .iter_mut()
        .find(|known| known.shard() == shard)
    {
        *known = frontier;
        return Ok(());
    }
    if state.frontiers.len() >= MAX_REPLAY_SHARDS {
        return Err(SchemaSessionFailure::ReplayLimitExceeded);
    }
    state.frontiers.push(frontier);
    state.frontiers.sort_by_key(|known| known.shard());
    Ok(())
}
