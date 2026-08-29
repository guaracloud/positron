use std::sync::{Arc, Mutex};

use positron_domain::identity::TenantId;
use positron_kernel::{ResourceReservation, TransferredResourceReservation};
use positron_signals::{SchemaCatalog, SchemaFailure, SchemaSessionStore};

use super::{MAX_REPLAY_SHARDS, SchemaSessionFailure, SessionState, TenantSchemaSession};

/// Immutable checkpoint view produced by a tenant schema session.
pub struct TenantSchemaCheckpoint {
    tenant: TenantId,
    catalog_bytes: Vec<u8>,
    entry_count: usize,
    overflow_record_count: u64,
    retained_charge_bytes: u64,
    pending_bytes: u64,
    base_charge_bytes: u64,
}

impl TenantSchemaSession {
    pub(crate) fn from_checkpoint(
        tenant: TenantId,
        bytes: &[u8],
        capacity: ResourceReservation<'_>,
        sidecar_capacity: Option<ResourceReservation<'_>>,
    ) -> Result<Self, SchemaSessionFailure> {
        let sidecar_bytes = u64::try_from(
            SchemaCatalog::catalog_sidecar_memory_bound(bytes)
                .map_err(SchemaSessionFailure::Schema)?,
        )
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        if sidecar_bytes == 0 {
            if sidecar_capacity.is_some() {
                return Err(SchemaSessionFailure::StateUnavailable);
            }
        } else if !sidecar_capacity.as_ref().is_some_and(|reservation| {
            reservation.authorizes_tenant_schema_session(tenant, sidecar_bytes)
        }) {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        let (catalog, decoded_frontiers) =
            SchemaSessionStore::from_checkpoint(capacity, tenant, bytes)
                .map_err(SchemaSessionFailure::Schema)?
                .ok_or(SchemaSessionFailure::TenantConflict)?;
        let budget = catalog.catalog().budget();
        let base_charge_bytes = catalog.capacity_bytes();
        let mut frontiers = Vec::new();
        frontiers
            .try_reserve_exact(MAX_REPLAY_SHARDS)
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        frontiers.extend(decoded_frontiers);
        let mut retained_capacity = Vec::<TransferredResourceReservation>::new();
        retained_capacity
            .try_reserve_exact(budget.max_entries())
            .map_err(|_| SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable))?;
        Ok(Self {
            state: Arc::new(Mutex::new(SessionState {
                tenant,
                catalog,
                frontiers,
                retained_capacity,
                query_capacity: sidecar_capacity.map(ResourceReservation::transfer),
                query_charge_bytes: sidecar_bytes,
                base_charge_bytes,
                retained_charge_bytes: 0,
                pending: None,
                in_flight: None,
                checkpoint_changed: false,
            })),
        })
    }

    /// Reports whether checkpoint-relevant state changed after this session
    /// was constructed from its recovery basis.
    ///
    /// The result is monotonic for the session lifetime because checkpoint
    /// publication is a terminal, quiescent lifecycle operation.
    pub fn has_checkpoint_changes(&self) -> Result<bool, SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        Ok(state.checkpoint_changed)
    }

    pub fn checkpoint(&self) -> Result<TenantSchemaCheckpoint, SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        Ok(TenantSchemaCheckpoint {
            tenant: state.tenant,
            catalog_bytes: state
                .catalog
                .catalog()
                .encode_checkpoint_object(&state.frontiers)
                .map_err(SchemaSessionFailure::Schema)?,
            entry_count: state.catalog.catalog().entry_count(),
            overflow_record_count: state.catalog.catalog().overflow_record_count(),
            retained_charge_bytes: state
                .retained_charge_bytes
                .checked_add(state.query_charge_bytes)
                .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
            pending_bytes: state
                .pending
                .as_ref()
                .map_or(0, |pending| pending.capacity_bytes),
            base_charge_bytes: state.base_charge_bytes,
        })
    }
}

impl TenantSchemaCheckpoint {
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn catalog_bytes(&self) -> &[u8] {
        &self.catalog_bytes
    }

    #[must_use]
    pub fn into_catalog_bytes(self) -> Vec<u8> {
        self.catalog_bytes
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    #[must_use]
    pub const fn overflow_record_count(&self) -> u64 {
        self.overflow_record_count
    }

    #[must_use]
    pub const fn retained_charge_bytes(&self) -> u64 {
        self.retained_charge_bytes
    }

    #[must_use]
    pub const fn pending_bytes(&self) -> u64 {
        self.pending_bytes
    }

    #[must_use]
    pub const fn base_charge_bytes(&self) -> u64 {
        self.base_charge_bytes
    }
}
