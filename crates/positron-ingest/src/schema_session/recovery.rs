use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::{
    LedgerSnapshot, ResourceAmounts, ResourceDimension, ResourceGovernor, ResourceReservation,
    StoreBlockIdentity, TransferredResourceReservation,
};
use positron_signals::{SchemaBudget, SchemaCheckpointFrontier};

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
            let digest = block
                .content_digest()
                .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
            let permit = state.permit;
            state
                .catalog
                .reconcile_block_identity(&permit, block.identity(), digest)
                .map_err(SchemaSessionFailure::Schema)?;
            let decode_capacity =
                reserve_replay_decode_capacity(tenant, block.payload().len(), governor)?;
            let delta = state
                .catalog
                .replay(&state.permit, tenant, snapshot, block)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            let retained_bytes = u64::try_from(delta.retained_memory_bytes())
                .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
            let capacity = resize_replay_capacity(decode_capacity, retained_bytes)?;
            state
                .catalog
                .commit(&permit, delta, block.identity(), digest)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            retain_capacity(&mut state, capacity, retained_bytes)?;
            set_frontier(
                &mut state,
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                digest,
            )?;
        }
        Ok(())
    }

    pub(crate) fn replay_snapshot_for_bootstrap(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        recovery: &mut ResourceReservation<'_>,
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
            let permit = state.permit;
            state
                .catalog
                .reconcile_block_identity(&permit, block.identity(), digest)
                .map_err(SchemaSessionFailure::Schema)?;
            ensure_replay_capacity(recovery, block.payload().len())?;
            let delta = state
                .catalog
                .replay(&state.permit, tenant, snapshot, block)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            state
                .catalog
                .commit(&permit, delta, block.identity(), digest)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            set_frontier(
                &mut state,
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                digest,
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
    let replayed = state
        .catalog
        .replay(&state.permit, state.tenant, snapshot, block)
        .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
    let retained_bytes = u64::try_from(replayed.retained_memory_bytes())
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    let next_retained = state
        .retained_charge_bytes
        .checked_add(retained_bytes)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    ensure_frontier_slot(state, shard)?;
    drop(decode_capacity);
    let permit = state.permit;
    state
        .catalog
        .commit(&permit, replayed, block.identity(), digest)
        .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
    set_frontier(state, shard, block.position(), identity, digest)?;
    let mut pending = state
        .pending
        .take()
        .ok_or(SchemaSessionFailure::StateUnavailable)?;
    if let Err(failure) = resize_pending_capacity(
        state,
        &mut pending.capacity,
        retained_bytes,
        next_retained,
        governor,
    ) {
        state.pending = Some(pending);
        return Err(failure);
    }
    drop(pending);
    Ok(())
}

fn resize_pending_capacity(
    state: &mut SessionState,
    pending_capacity: &mut Option<TransferredResourceReservation>,
    retained_bytes: u64,
    next_retained: u64,
    governor: ResourceGovernor<'_>,
) -> Result<(), SchemaSessionFailure> {
    let Some(capacity) = pending_capacity.take() else {
        return if retained_bytes == 0 {
            Ok(())
        } else {
            Err(SchemaSessionFailure::StateUnavailable)
        };
    };
    if !capacity.can_reclaim_with(governor) {
        *pending_capacity = Some(capacity);
        return Err(SchemaSessionFailure::StateUnavailable);
    }
    if retained_bytes == 0 {
        capacity.release(governor);
        return Ok(());
    }
    let mut capacity = capacity
        .reclaim(governor)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
    let amounts = match ResourceAmounts::only(ResourceDimension::MemoryBytes, retained_bytes) {
        Ok(amounts) => amounts,
        Err(_) => {
            *pending_capacity = Some(capacity.transfer());
            return Err(SchemaSessionFailure::ReplayLimitExceeded);
        },
    };
    if capacity.try_resize(amounts).is_err() {
        *pending_capacity = capacity.is_active().then(|| capacity.transfer());
        return Err(SchemaSessionFailure::StateUnavailable);
    }
    state.retained_capacity.push(capacity.transfer());
    state.retained_charge_bytes = next_retained;
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
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes)
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    let claim =
        positron_kernel::WorkClaim::tenant(tenant, positron_kernel::WorkKind::Ingest, amounts)
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    governor
        .reserve(claim)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
}

pub(super) fn reserve_query_index_capacity(
    tenant: TenantId,
    payload_bytes: usize,
    governor: ResourceGovernor<'_>,
) -> Result<ResourceReservation<'_>, SchemaSessionFailure> {
    reserve_replay_decode_capacity(tenant, payload_bytes, governor)
}

fn resize_replay_capacity(
    mut capacity: ResourceReservation<'_>,
    retained_bytes: u64,
) -> Result<Option<TransferredResourceReservation>, SchemaSessionFailure> {
    if retained_bytes == 0 {
        return Ok(None);
    }
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, retained_bytes)
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
    capacity
        .try_resize(amounts)
        .map_err(|_| SchemaSessionFailure::StateUnavailable)
        .map(|_| Some(capacity.transfer()))
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
