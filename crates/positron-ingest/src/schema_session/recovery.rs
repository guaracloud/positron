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
    ReplaySnapshotBounds, ensure_replay_capacity, extend_replay_work, replay_snapshot_block_work,
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
        let catalog_clone_work = state
            .catalog
            .catalog()
            .replay_clone_work_units()
            .map_err(SchemaSessionFailure::Schema)?;
        let catalog_mutation_work = state
            .catalog
            .catalog()
            .replay_mutation_setup_work_units()
            .map_err(SchemaSessionFailure::Schema)?;
        let catalog_reconciliation_work = state
            .catalog
            .replay_reconciliation_work_units_with_staged_entries(block_count, 1)
            .map_err(SchemaSessionFailure::Schema)?;
        let bounds = ReplaySnapshotBounds::new(
            block_count,
            total_payload_bytes,
            maximum_payload_bytes,
            mandatory_work,
            optional_work,
            state.catalog.catalog().memory_bytes(),
            catalog_clone_work
                .checked_add(catalog_mutation_work)
                .and_then(|work| work.checked_add(catalog_reconciliation_work))
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
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
            .try_clone_for_replay_observed(replay_capacity, &mandatory_observer)
            .map_err(SchemaSessionFailure::Schema)?;
        candidate_catalog
            .prepare_replay_mutation_observed(&mandatory_observer)
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
            let baseline = candidate_catalog
                .replay_reconciliation_work_units_with_staged_entries(1, 1)
                .map_err(SchemaSessionFailure::Schema)?;
            let actual = candidate_catalog
                .replay_delta_work_units(&delta, block.identity())
                .map_err(SchemaSessionFailure::Schema)?;
            admit_replay_delta_work(
                candidate_catalog.replay_reservation(),
                &mandatory_observer,
                baseline,
                actual,
                cancellation,
            )?;
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
                .reconcile_block_identity_observed(block.identity(), digest, &mandatory_observer)
                .map_err(SchemaSessionFailure::Schema)?;
            candidate_catalog
                .commit_observed(delta, block.identity(), digest, &mandatory_observer)
                .map_err(map_replay_observed_failure)?;
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
        state.checkpoint_changed = true;
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
            let reconciliation_work = state
                .catalog
                .replay_reconciliation_work_units_with_staged_entries(1, 1)
                .map_err(SchemaSessionFailure::Schema)?;
            resize_replay_work(recovery, block.payload().len(), reconciliation_work)?;
            ensure_replay_capacity(recovery, block.payload().len())?;
            let observer = SchemaBuildObserver::new_scan(
                recovery.granted().get(ResourceDimension::CpuWorkUnits),
                cancellation,
            );
            // Bootstrap reserves only the mandatory decode/discovery budget.
            // Text evidence is optional and must not consume that reservation;
            // serving replay admits it separately when capacity is available.
            let delta = state
                .catalog
                .replay_observed_cancellable_with_text_observer(
                    tenant,
                    snapshot,
                    block,
                    cancellation,
                    &observer,
                    None,
                )
                .map_err(map_replay_observed_failure)?;
            let baseline = state
                .catalog
                .replay_reconciliation_work_units_with_staged_entries(1, 1)
                .map_err(SchemaSessionFailure::Schema)?;
            let actual = state
                .catalog
                .replay_delta_work_units(&delta, block.identity())
                .map_err(SchemaSessionFailure::Schema)?;
            admit_replay_delta_work(recovery, &observer, baseline, actual, cancellation)?;
            ensure_frontier_slot(&state, snapshot.scope().shard_id())?;
            let frontier = validated_frontier(
                snapshot.scope().shard_id(),
                block.position(),
                block.identity(),
                digest,
            )?;
            state
                .catalog
                .reconcile_block_identity_observed(block.identity(), digest, &observer)
                .map_err(SchemaSessionFailure::Schema)?;
            state
                .catalog
                .commit_observed(delta, block.identity(), digest, &observer)
                .map_err(map_replay_observed_failure)?;
            publish_frontier(&mut state, frontier);
            state.checkpoint_changed = true;
        }
        Ok(())
    }
}

fn admit_replay_delta_work(
    reservation: &mut ResourceReservation<'_>,
    observer: &SchemaBuildObserver<'_>,
    baseline: u64,
    actual: u64,
    cancellation: &dyn ScanCancellation,
) -> Result<(), SchemaSessionFailure> {
    if cancellation.is_cancelled() {
        return Err(SchemaSessionFailure::Cancelled);
    }
    let additional = actual.saturating_sub(baseline);
    extend_replay_work(reservation, additional)?;
    observer
        .increase_limit(additional)
        .map_err(map_observation_failure)
}
