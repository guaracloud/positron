use std::sync::{Arc, Mutex};

use positron_domain::identity::TenantId;
use positron_kernel::TransferredResourceReservation;
use positron_signals::{SchemaCatalog, SchemaFailure, TenantSchemaState};

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
    ) -> Result<Self, SchemaSessionFailure> {
        let (catalog, decoded_frontiers) =
            SchemaCatalog::decode_checkpoint_object(bytes).map_err(SchemaSessionFailure::Schema)?;
        if catalog.tenant() != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        let budget = catalog.budget();
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
                catalog: TenantSchemaState::from_catalog(catalog),
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
            retained_charge_bytes: state.retained_charge_bytes,
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
