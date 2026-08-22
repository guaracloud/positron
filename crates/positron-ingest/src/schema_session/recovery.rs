use positron_domain::identity::TenantId;
use positron_kernel::{LedgerSnapshot, ResourceDimension, ResourceGovernor, ResourceReservation};
use positron_signals::{ScanCancellation, ScanObserver};

use super::SchemaBuildObserver;
pub(super) use super::recovery_support::{
    ensure_frontier_slot, ensure_frontier_slot_values, map_observation_failure,
    map_replay_observed_failure, publish_frontier, publish_frontier_values, reconcile_pending,
    reserve_schema_memory, validated_frontier, verify_frontier,
};
use super::replay_capacity::{
    ensure_replay_capacity, replay_snapshot_work_bounds, reserve_replay_snapshot_capacity,
    resize_replay_work,
};
use super::{MAX_REPLAY_SHARDS, SchemaFailure, SchemaSessionFailure, TenantSchemaSession};

pub(super) use super::replay_capacity::reserve_query_index_capacity;

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
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(snapshot.blocks().len())
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        for block in snapshot
            .blocks()
            .iter()
            .filter(|block| frontier.is_none_or(|known| block.position() > known.position()))
        {
            if cancellation.is_cancelled() {
                return Err(SchemaSessionFailure::Cancelled);
            }
            blocks.push(block);
        }
        if blocks.is_empty() {
            return Ok(());
        }
        let mut payload_bytes = Vec::new();
        payload_bytes
            .try_reserve_exact(blocks.len())
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        let mut digests = Vec::new();
        digests
            .try_reserve_exact(blocks.len())
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        for block in &blocks {
            if cancellation.is_cancelled() {
                return Err(SchemaSessionFailure::Cancelled);
            }
            payload_bytes.push(block.payload().len());
            digests.push(
                block
                    .content_digest()
                    .map_err(|_| SchemaSessionFailure::StateUnavailable)?,
            );
        }
        let (replay_capacity, complete_text) =
            reserve_replay_snapshot_capacity(tenant, &payload_bytes, governor)?;
        let replay_work = replay_capacity
            .granted()
            .get(ResourceDimension::CpuWorkUnits);
        let (mandatory_work, optional_work) = replay_snapshot_work_bounds(&payload_bytes)?;
        if replay_work < mandatory_work {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        let mandatory_observer = SchemaBuildObserver::new_scan(mandatory_work, cancellation);
        let optional_observer =
            complete_text.then(|| SchemaBuildObserver::new_scan(optional_work, cancellation));
        let mut candidate_catalog = state
            .catalog
            .try_clone_with_reservation(replay_capacity)
            .map_err(SchemaSessionFailure::Schema)?;
        let mut candidate_frontiers = Vec::new();
        candidate_frontiers
            .try_reserve_exact(MAX_REPLAY_SHARDS)
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        candidate_frontiers.extend_from_slice(&state.frontiers);
        let mut new_retained_capacity = Vec::new();
        new_retained_capacity
            .try_reserve_exact(blocks.len())
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        let mut candidate_retained_charge = state.retained_charge_bytes;
        for (block, digest) in blocks.iter().zip(&digests) {
            if cancellation.is_cancelled() {
                return Err(SchemaSessionFailure::Cancelled);
            }
            mandatory_observer
                .observe_work(1)
                .map_err(map_observation_failure)?;
            let delta = candidate_catalog
                .replay_observed_cancellable_with_text_observer(
                    tenant,
                    snapshot,
                    block,
                    cancellation,
                    &mandatory_observer,
                    optional_observer
                        .as_ref()
                        .map(|observer| observer as &dyn positron_signals::ScanObserver),
                )
                .map_err(map_replay_observed_failure)?;
            let retained_bytes = u64::try_from(delta.retained_memory_bytes())
                .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
            let next_retained = candidate_retained_charge
                .checked_add(retained_bytes)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
            let capacity = reserve_schema_memory(tenant, retained_bytes, governor)?;
            if capacity.is_some()
                && state.retained_capacity.len() + new_retained_capacity.len()
                    >= state.retained_capacity.capacity()
            {
                return Err(SchemaSessionFailure::ReplayLimitExceeded);
            }
            ensure_frontier_slot_values(&candidate_frontiers, snapshot.scope().shard_id())?;
            let frontier = validated_frontier(
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                *digest,
            )?;
            candidate_catalog
                .reconcile_block_identity(block.identity(), *digest)
                .map_err(SchemaSessionFailure::Schema)?;
            candidate_catalog
                .commit(delta, block.identity(), *digest)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            if let Some(capacity) = capacity {
                new_retained_capacity.push(capacity.transfer());
            }
            candidate_retained_charge = next_retained;
            publish_frontier_values(&mut candidate_frontiers, frontier);
        }
        if cancellation.is_cancelled() {
            return Err(SchemaSessionFailure::Cancelled);
        }
        let old_catalog = std::mem::replace(&mut state.catalog, candidate_catalog);
        drop(old_catalog);
        state.frontiers = candidate_frontiers;
        state.retained_capacity.extend(new_retained_capacity);
        state.retained_charge_bytes = candidate_retained_charge;
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
            resize_replay_work(recovery, block.payload().len())?;
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
