use std::sync::{Arc, Mutex};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::{
    ResourceGovernor, ResourceReservation, StoreBlockIdentity, TransferredResourceReservation,
};
use positron_signals::{
    SchemaBudget, SchemaCatalog, SchemaCheckpointFrontier, SchemaDelta, SchemaFailure,
    SchemaSessionStore,
};

mod checkpoint;
mod inspection;
mod observer;
mod recovery;
mod recovery_support;
mod registry;
mod replay_capacity;
mod stage;
pub use checkpoint::TenantSchemaCheckpoint;
pub(crate) use observer::SchemaBuildObserver;
use recovery::{
    ensure_frontier_slot, reconcile_pending, reserve_schema_memory, validated_frontier,
};
pub use registry::TenantSchemaRegistry;

const MAX_REPLAY_SHARDS: usize = 4_096;

#[derive(Clone)]
pub struct TenantSchemaSession {
    state: Arc<Mutex<SessionState>>,
}

pub(super) struct SessionState {
    pub(super) tenant: TenantId,
    pub(super) catalog: SchemaSessionStore,
    pub(super) frontiers: Vec<SchemaCheckpointFrontier>,
    pub(super) retained_capacity: Vec<TransferredResourceReservation>,
    pub(super) query_capacity: Option<TransferredResourceReservation>,
    pub(super) query_charge_bytes: u64,
    pub(super) base_charge_bytes: u64,
    pub(super) retained_charge_bytes: u64,
    pub(super) pending: Option<PendingStage>,
    pub(super) in_flight: Option<StoreBlockIdentity>,
    pub(super) checkpoint_changed: bool,
}

pub(super) struct PendingStage {
    pub(super) identity: StoreBlockIdentity,
    pub(super) shard: VirtualShardId,
    pub(super) delta: SchemaDelta,
    pub(super) capacity: Option<TransferredResourceReservation>,
    pub(super) capacity_bytes: u64,
    pub(super) digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaSessionFailure {
    TenantConflict,
    Schema(SchemaFailure),
    StateUnavailable,
    Cancelled,
    ReplayLimitExceeded,
    RegistryLimitExceeded,
    InFlight,
    PendingReconciliationRequired,
    ReplayIntegrity,
    LogStore(positron_signals::LogStoreFailureCode),
}

impl std::fmt::Display for SchemaSessionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant schema session unavailable")
    }
}

impl std::error::Error for SchemaSessionFailure {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DurableSchemaOutcome {
    Committed {
        position: CommitPosition,
        digest: [u8; 32],
    },
    DefiniteFailure,
    Ambiguous {
        digest: [u8; 32],
    },
}

pub(crate) struct DurableSchemaResolution {
    pub(crate) identity: StoreBlockIdentity,
    pub(crate) shard: VirtualShardId,
    pub(crate) staged: SchemaDelta,
    pub(crate) capacity: Option<TransferredResourceReservation>,
    pub(crate) capacity_bytes: u64,
    pub(crate) outcome: DurableSchemaOutcome,
}

impl TenantSchemaSession {
    pub(crate) fn release_1(
        tenant: TenantId,
        capacity: ResourceReservation<'_>,
    ) -> Result<Self, SchemaSessionFailure> {
        let budget = SchemaBudget::release_1().map_err(SchemaSessionFailure::Schema)?;
        Self::with_budget(tenant, budget, capacity)
    }

    pub(crate) fn release_1_base_memory_bytes() -> Result<u64, SchemaSessionFailure> {
        let budget = SchemaBudget::release_1().map_err(SchemaSessionFailure::Schema)?;
        let bytes = SchemaCatalog::base_memory_bound(budget)
            .map_err(SchemaSessionFailure::Schema)?
            .checked_add(
                MAX_REPLAY_SHARDS
                    .checked_mul(std::mem::size_of::<SchemaCheckpointFrontier>())
                    .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    budget
                        .max_entries()
                        .checked_mul(std::mem::size_of::<TransferredResourceReservation>())?,
                )
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SessionState>()))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<(TenantId, TenantSchemaSession)>())
            })
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        u64::try_from(bytes).map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)
    }

    pub(crate) fn checkpoint_construction_capacity_bytes(
        bytes: &[u8],
    ) -> Result<(u64, u64), SchemaSessionFailure> {
        let catalog =
            SchemaCatalog::catalog_memory_bound(bytes).map_err(SchemaSessionFailure::Schema)?;
        let sidecar = SchemaCatalog::catalog_sidecar_memory_bound(bytes)
            .map_err(SchemaSessionFailure::Schema)?;
        let structural = MAX_REPLAY_SHARDS
            .checked_mul(std::mem::size_of::<SchemaCheckpointFrontier>())
            .and_then(|value| {
                value.checked_add(
                    SchemaBudget::system_max_entries()
                        .checked_mul(std::mem::size_of::<TransferredResourceReservation>())?,
                )
            })
            .and_then(|value| value.checked_add(std::mem::size_of::<SessionState>()))
            .and_then(|value| {
                value.checked_add(std::mem::size_of::<(TenantId, TenantSchemaSession)>())
            })
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        let base = catalog
            .checked_sub(sidecar)
            .and_then(|catalog| catalog.checked_add(structural))
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        Ok((
            u64::try_from(base).map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?,
            u64::try_from(sidecar).map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?,
        ))
    }

    fn with_budget(
        tenant: TenantId,
        budget: SchemaBudget,
        capacity: ResourceReservation<'_>,
    ) -> Result<Self, SchemaSessionFailure> {
        let catalog = SchemaSessionStore::new(capacity, tenant, budget)
            .map_err(SchemaSessionFailure::Schema)?;
        let base_charge_bytes = catalog.capacity_bytes();
        let mut frontiers = Vec::new();
        frontiers
            .try_reserve_exact(MAX_REPLAY_SHARDS)
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        let mut retained_capacity = Vec::new();
        retained_capacity
            .try_reserve_exact(budget.max_entries())
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        Ok(Self {
            state: Arc::new(Mutex::new(SessionState {
                tenant,
                catalog,
                frontiers,
                retained_capacity,
                query_capacity: None,
                query_charge_bytes: 0,
                base_charge_bytes,
                retained_charge_bytes: 0,
                pending: None,
                in_flight: None,
                checkpoint_changed: false,
            })),
        })
    }

    pub(crate) fn resolve_durable_outcome(
        &self,
        resolution: DurableSchemaResolution,
        governor: ResourceGovernor<'_>,
    ) -> Result<(), SchemaSessionFailure> {
        let DurableSchemaResolution {
            identity,
            shard,
            staged,
            capacity,
            capacity_bytes,
            outcome,
        } = resolution;
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.in_flight != Some(identity) {
            return Err(SchemaSessionFailure::InFlight);
        }
        match outcome {
            DurableSchemaOutcome::Committed { position, digest } => {
                if state.pending.is_some() {
                    return Err(SchemaSessionFailure::InFlight);
                }
                state.pending = Some(PendingStage {
                    identity,
                    shard,
                    delta: staged,
                    capacity,
                    capacity_bytes,
                    digest,
                });
                if !state.catalog.governed_by(governor) {
                    return Err(SchemaSessionFailure::StateUnavailable);
                }
                ensure_frontier_slot(&state, shard)?;
                let frontier = validated_frontier(shard, position, identity, digest)?;
                let next_retained = state
                    .retained_charge_bytes
                    .checked_add(capacity_bytes)
                    .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
                if state
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.capacity.is_some())
                    && state.retained_capacity.len() == state.retained_capacity.capacity()
                {
                    return Err(SchemaSessionFailure::ReplayLimitExceeded);
                }
                let staged_bytes = state
                    .pending
                    .as_ref()
                    .ok_or(SchemaSessionFailure::StateUnavailable)?
                    .delta
                    .staged_memory_bytes();
                let _clone_capacity = reserve_schema_memory(
                    state.tenant,
                    u64::try_from(staged_bytes)
                        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?,
                    governor,
                )?;
                let commit_delta = state
                    .pending
                    .as_ref()
                    .ok_or(SchemaSessionFailure::StateUnavailable)?
                    .delta
                    .try_clone()
                    .map_err(SchemaSessionFailure::Schema)?;
                state
                    .catalog
                    .commit(commit_delta, identity, digest)
                    .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::InvalidValue))?;
                recovery::publish_frontier(&mut state, frontier);
                let completed = state
                    .pending
                    .take()
                    .ok_or(SchemaSessionFailure::StateUnavailable)?;
                if let Some(capacity) = completed.capacity {
                    state.retained_capacity.push(capacity);
                }
                state.retained_charge_bytes = next_retained;
                state.in_flight = None;
                state.checkpoint_changed = true;
            },
            DurableSchemaOutcome::DefiniteFailure => {
                state.in_flight = None;
                drop(capacity);
            },
            DurableSchemaOutcome::Ambiguous { digest } => {
                state.in_flight = None;
                state.pending = Some(PendingStage {
                    identity,
                    shard,
                    delta: staged,
                    capacity,
                    capacity_bytes,
                    digest,
                });
            },
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "schema_session/tests/mod.rs"]
mod tests;
