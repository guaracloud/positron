use std::sync::{Arc, Mutex};

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, VirtualShardId};
use positron_kernel::{
    LedgerSnapshot, ResourceGovernor, StoreBlockIdentity, TransferredResourceReservation,
};
use positron_signals::{
    LogRecord, SchemaBudget, SchemaCatalog, SchemaCheckpointFrontier, SchemaDelta, SchemaFailure,
    TenantSchemaState,
};

mod checkpoint;
mod recovery;
mod registry;
pub use checkpoint::TenantSchemaCheckpoint;
use recovery::{ensure_frontier_slot, reconcile_pending, set_frontier};
pub use registry::TenantSchemaRegistry;

const MAX_REPLAY_SHARDS: usize = 4_096;

#[derive(Clone)]
pub struct TenantSchemaSession {
    state: Arc<Mutex<SessionState>>,
}

pub(super) struct SessionState {
    pub(super) tenant: TenantId,
    pub(super) catalog: TenantSchemaState,
    pub(super) frontiers: Vec<SchemaCheckpointFrontier>,
    pub(super) retained_capacity: Vec<TransferredResourceReservation>,
    pub(super) base_capacity: Option<TransferredResourceReservation>,
    pub(super) base_charge_bytes: u64,
    pub(super) retained_charge_bytes: u64,
    pub(super) pending: Option<PendingStage>,
    pub(super) in_flight: Option<StoreBlockIdentity>,
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
    ReplayLimitExceeded,
    RegistryLimitExceeded,
    InFlight,
    PendingReconciliationRequired,
    ReplayIntegrity,
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

impl TenantSchemaSession {
    pub(crate) fn release_1(tenant: TenantId) -> Result<Self, SchemaSessionFailure> {
        let budget = SchemaBudget::release_1().map_err(SchemaSessionFailure::Schema)?;
        Self::with_budget(tenant, budget)
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

    fn with_budget(tenant: TenantId, budget: SchemaBudget) -> Result<Self, SchemaSessionFailure> {
        let catalog =
            TenantSchemaState::new(tenant, budget).map_err(SchemaSessionFailure::Schema)?;
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
                base_capacity: None,
                base_charge_bytes: 0,
                retained_charge_bytes: 0,
                pending: None,
                in_flight: None,
            })),
        })
    }

    pub(super) fn base_memory_bytes(&self) -> Result<u64, SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        let bytes = state
            .catalog
            .catalog()
            .memory_bytes()
            .checked_add(
                state
                    .frontiers
                    .capacity()
                    .checked_mul(std::mem::size_of::<SchemaCheckpointFrontier>())
                    .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    state
                        .retained_capacity
                        .capacity()
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

    fn attach_base_capacity(
        &self,
        capacity: TransferredResourceReservation,
        bytes: u64,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.base_capacity.is_some() {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        state.base_capacity = Some(capacity);
        state.base_charge_bytes = bytes;
        Ok(())
    }

    pub(crate) fn stage_group(
        &self,
        tenant: TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        snapshot: &LedgerSnapshot<'_>,
        records: &mut [LogRecord],
        governor: ResourceGovernor<'_>,
    ) -> Result<SchemaDelta, SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if tenant != state.tenant || snapshot.scope().tenant_id() != state.tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        if state.in_flight.is_some() {
            return Err(SchemaSessionFailure::InFlight);
        }
        reconcile_pending(&mut state, snapshot, governor)?;
        ensure_frontier_slot(&state, shard)?;
        let delta = state
            .catalog
            .stage_group(records)
            .map_err(|failure| match failure.code() {
                positron_signals::LogStoreFailureCode::InvalidInput
                | positron_signals::LogStoreFailureCode::MalformedBlock
                | positron_signals::LogStoreFailureCode::PhysicalScopeMismatch => {
                    SchemaSessionFailure::Schema(SchemaFailure::InvalidValue)
                },
                positron_signals::LogStoreFailureCode::LimitExceeded => {
                    SchemaSessionFailure::Schema(SchemaFailure::LimitExceeded)
                },
                positron_signals::LogStoreFailureCode::ResourceExhausted
                | positron_signals::LogStoreFailureCode::ResourceAdmissionRefused
                | positron_signals::LogStoreFailureCode::ClockUnavailable
                | positron_signals::LogStoreFailureCode::Kernel => {
                    SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable)
                },
            })?;
        state.in_flight = Some(identity);
        Ok(delta)
    }

    pub(crate) fn resolve_durable_outcome(
        &self,
        identity: StoreBlockIdentity,
        shard: VirtualShardId,
        staged: SchemaDelta,
        capacity: Option<TransferredResourceReservation>,
        capacity_bytes: u64,
        outcome: DurableSchemaOutcome,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.in_flight != Some(identity) {
            return Err(SchemaSessionFailure::InFlight);
        }
        state.in_flight = None;
        match outcome {
            DurableSchemaOutcome::Committed { position, digest } => {
                state
                    .catalog
                    .commit(staged, identity, digest)
                    .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::InvalidValue))?;
                set_frontier(&mut state, shard, position, identity, digest)?;
                if let Some(capacity) = capacity {
                    state.retained_capacity.push(capacity);
                }
                state.retained_charge_bytes = state
                    .retained_charge_bytes
                    .checked_add(capacity_bytes)
                    .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
                state.pending = None;
            },
            DurableSchemaOutcome::DefiniteFailure => drop(capacity),
            DurableSchemaOutcome::Ambiguous { digest } => {
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
