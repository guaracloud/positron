use std::sync::{Arc, Mutex};

use positron_domain::identity::TenantId;
use positron_kernel::{ResourceAmounts, ResourceDimension, ResourceGovernor, WorkClaim, WorkKind};

use super::{SchemaSessionFailure, TenantSchemaSession};

const MAX_TENANT_SCHEMA_SESSIONS: usize = 4_096;

/// Bounded process registry that resolves exactly one schema session per tenant.
#[derive(Clone)]
pub struct TenantSchemaRegistry {
    state: Arc<Mutex<RegistryState>>,
}

struct RegistryState {
    sessions: Vec<(TenantId, TenantSchemaSession)>,
    maximum: usize,
}

impl TenantSchemaRegistry {
    pub fn new(maximum: usize) -> Result<Self, SchemaSessionFailure> {
        if maximum == 0 || maximum > MAX_TENANT_SCHEMA_SESSIONS {
            return Err(SchemaSessionFailure::RegistryLimitExceeded);
        }
        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(maximum)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        Ok(Self {
            state: Arc::new(Mutex::new(RegistryState { sessions, maximum })),
        })
    }

    pub fn session(
        &self,
        tenant: TenantId,
        governor: ResourceGovernor<'_>,
    ) -> Result<TenantSchemaSession, SchemaSessionFailure> {
        self.session_inner(tenant, None, governor)
    }

    pub fn session_from_checkpoint(
        &self,
        tenant: TenantId,
        checkpoint: &[u8],
        governor: ResourceGovernor<'_>,
    ) -> Result<TenantSchemaSession, SchemaSessionFailure> {
        self.session_inner(tenant, Some(checkpoint), governor)
    }

    fn session_inner(
        &self,
        tenant: TenantId,
        checkpoint: Option<&[u8]>,
        governor: ResourceGovernor<'_>,
    ) -> Result<TenantSchemaSession, SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        match state
            .sessions
            .binary_search_by_key(&tenant, |(known, _)| *known)
        {
            Ok(index) => state
                .sessions
                .get(index)
                .map(|(_, session)| session.clone())
                .ok_or(SchemaSessionFailure::StateUnavailable),
            Err(index) => {
                if state.sessions.len() >= state.maximum {
                    return Err(SchemaSessionFailure::RegistryLimitExceeded);
                }
                let session = match checkpoint {
                    Some(bytes) => TenantSchemaSession::from_checkpoint(tenant, bytes)?,
                    None => TenantSchemaSession::release_1(tenant)?,
                };
                let base_bytes = session.base_memory_bytes()?;
                let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, base_bytes)
                    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
                let claim = WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)
                    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
                let capacity = governor
                    .reserve(claim)
                    .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
                session.attach_base_capacity(capacity.transfer(), base_bytes)?;
                state.sessions.insert(index, (tenant, session.clone()));
                Ok(session)
            },
        }
    }
}
