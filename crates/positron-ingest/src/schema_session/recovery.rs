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
    ReplaySnapshotBounds, ensure_replay_capacity, replay_snapshot_block_work,
    reserve_replay_snapshot_capacity, resize_replay_work,
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
        let mut block_count = 0_usize;
        let mut total_payload_bytes = 0_usize;
        let mut maximum_payload_bytes = 0_usize;
        let mut mandatory_work = 0_u64;
        let mut optional_work = 0_u64;
        for block in snapshot
            .blocks()
            .iter()
            .filter(|block| frontier.is_none_or(|known| block.position() > known.position()))
        {
            if cancellation.is_cancelled() {
                return Err(SchemaSessionFailure::Cancelled);
            }
            block_count = block_count
                .checked_add(1)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
            let payload_bytes = block.payload().len();
            total_payload_bytes = total_payload_bytes
                .checked_add(payload_bytes)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
            maximum_payload_bytes = maximum_payload_bytes.max(payload_bytes);
            let (block_mandatory, block_optional) = replay_snapshot_block_work(payload_bytes)?;
            mandatory_work = mandatory_work
                .checked_add(block_mandatory)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
            optional_work = optional_work
                .checked_add(block_optional)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        }
        if block_count == 0 {
            return Ok(());
        }
        let bounds = ReplaySnapshotBounds::new(
            block_count,
            total_payload_bytes,
            maximum_payload_bytes,
            mandatory_work,
            optional_work,
            state.catalog.catalog().memory_bytes(),
        )?;
        debug_assert!(bounds.total_payload_bytes >= bounds.maximum_payload_bytes);
        let (replay_capacity, complete_text) =
            reserve_replay_snapshot_capacity(tenant, bounds, governor)?;
        let replay_work = replay_capacity
            .granted()
            .get(ResourceDimension::CpuWorkUnits);
        if replay_work < bounds.mandatory_work {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        let mandatory_observer = SchemaBuildObserver::new_scan(bounds.mandatory_work, cancellation);
        let optional_observer = complete_text
            .then(|| SchemaBuildObserver::new_scan(bounds.optional_work, cancellation));
        let mut candidate_catalog = state
            .catalog
            .try_clone_for_replay(&replay_capacity)
            .map_err(SchemaSessionFailure::Schema)?;
        let mut candidate_frontiers = Vec::new();
        candidate_frontiers
            .try_reserve_exact(MAX_REPLAY_SHARDS)
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        candidate_frontiers.extend_from_slice(&state.frontiers);
        let mut new_retained_capacity = Vec::new();
        new_retained_capacity
            .try_reserve_exact(bounds.block_count)
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        let mut candidate_retained_charge = state.retained_charge_bytes;
        let mut processed_blocks = 0_usize;
        for block in snapshot
            .blocks()
            .iter()
            .filter(|block| frontier.is_none_or(|known| block.position() > known.position()))
        {
            if cancellation.is_cancelled() {
                return Err(SchemaSessionFailure::Cancelled);
            }
            processed_blocks = processed_blocks
                .checked_add(1)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
            let digest = block
                .content_digest()
                .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
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
                digest,
            )?;
            candidate_catalog
                .reconcile_block_identity(block.identity(), digest)
                .map_err(SchemaSessionFailure::Schema)?;
            candidate_catalog
                .commit(delta, block.identity(), digest)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            if let Some(capacity) = capacity {
                new_retained_capacity.push(capacity.transfer());
            }
            candidate_retained_charge = next_retained;
            publish_frontier_values(&mut candidate_frontiers, frontier);
        }
        if processed_blocks != bounds.block_count {
            return Err(SchemaSessionFailure::ReplayLimitExceeded);
        }
        if cancellation.is_cancelled() {
            return Err(SchemaSessionFailure::Cancelled);
        }
        state
            .catalog
            .commit_replay_candidate(candidate_catalog)
            .map_err(SchemaSessionFailure::Schema)?;
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
