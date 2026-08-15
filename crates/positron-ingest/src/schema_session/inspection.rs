use positron_domain::identity::TenantId;
use positron_kernel::{LedgerSnapshot, ResourceGovernor, StoreBlockIdentity};

use super::{SchemaSessionFailure, TenantSchemaSession, recovery};

impl TenantSchemaSession {
    pub(crate) fn append_reachable_indexes(
        &self,
        snapshot: &LedgerSnapshot<'_>,
        reachable: &mut Vec<(StoreBlockIdentity, [u8; 32])>,
    ) -> Result<(), SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        for block in snapshot.blocks() {
            let digest = block
                .content_digest()
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            if !state.catalog.has_verified_block(block.identity(), digest) {
                continue;
            }
            let Err(position) = reachable.binary_search(&(block.identity(), digest)) else {
                continue;
            };
            if reachable.len() == positron_signals::SchemaBudget::system_max_entries() {
                return Err(SchemaSessionFailure::ReplayLimitExceeded);
            }
            reachable
                .try_reserve_exact(1)
                .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
            reachable.insert(position, (block.identity(), digest));
        }
        Ok(())
    }

    pub(crate) fn retain_reachable_indexes(
        &self,
        reachable: &[(StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        let permit = state.permit;
        state
            .catalog
            .retain_reachable_indexes(&permit, reachable)
            .map_err(SchemaSessionFailure::Schema)
    }

    pub fn discover(
        &self,
        tenant: TenantId,
        request: positron_signals::SchemaDiscoveryRequest,
    ) -> Result<positron_signals::SchemaDiscovery, SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.tenant != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        state
            .catalog
            .catalog()
            .discover(request)
            .map_err(SchemaSessionFailure::Schema)
    }

    pub fn record_query_use(
        &self,
        tenant: TenantId,
        path: &positron_signals::SchemaPath,
        snapshot: &LedgerSnapshot<'_>,
        governor: ResourceGovernor<'_>,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.tenant != tenant || snapshot.scope().tenant_id() != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        if state.in_flight.is_some() || state.pending.is_some() {
            return Err(SchemaSessionFailure::InFlight);
        }
        let permit = state.permit;
        state
            .catalog
            .record_query_use(&permit, path)
            .map_err(SchemaSessionFailure::Schema)?;
        for block in snapshot.blocks() {
            let capacity =
                recovery::reserve_query_index_capacity(tenant, block.payload().len(), governor)?;
            state
                .catalog
                .index_replayed_query_path(&permit, tenant, snapshot, block, path)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            drop(capacity);
        }
        Ok(())
    }

    pub fn remove_query_evidence(
        &self,
        tenant: TenantId,
        path: &positron_signals::SchemaPath,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.tenant != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        let permit = state.permit;
        state
            .catalog
            .remove_query_evidence(&permit, path)
            .map_err(SchemaSessionFailure::Schema)
    }
}
