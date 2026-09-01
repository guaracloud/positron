use positron_domain::routing::VirtualShardId;
use positron_kernel::{LedgerSnapshot, ResourceGovernor, StoreBlockIdentity};
use positron_signals::{LogRecord, ScanObserver, SchemaDelta};

use super::{SchemaSessionFailure, TenantSchemaSession, ensure_frontier_slot, reconcile_pending};

impl TenantSchemaSession {
    #[cfg(test)]
    pub(crate) fn stage_group(
        &self,
        tenant: positron_domain::identity::TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        snapshot: &LedgerSnapshot<'_>,
        records: &mut [LogRecord],
        governor: ResourceGovernor<'_>,
    ) -> Result<SchemaDelta, SchemaSessionFailure> {
        self.stage_group_inner(tenant, shard, identity, snapshot, records, governor, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_group_observed(
        &self,
        tenant: positron_domain::identity::TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        snapshot: &LedgerSnapshot<'_>,
        records: &mut [LogRecord],
        governor: ResourceGovernor<'_>,
        observer: &dyn ScanObserver,
    ) -> Result<SchemaDelta, SchemaSessionFailure> {
        self.stage_group_inner(
            tenant,
            shard,
            identity,
            snapshot,
            records,
            governor,
            Some(observer),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_group_inner(
        &self,
        tenant: positron_domain::identity::TenantId,
        shard: VirtualShardId,
        identity: StoreBlockIdentity,
        snapshot: &LedgerSnapshot<'_>,
        records: &mut [LogRecord],
        governor: ResourceGovernor<'_>,
        observer: Option<&dyn ScanObserver>,
    ) -> Result<SchemaDelta, SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if tenant != state.tenant || snapshot.scope().tenant_id() != state.tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        if !state.catalog.governed_by(governor) {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        if state.pending.is_some() {
            reconcile_pending(&mut state, snapshot, governor)?;
        }
        if state.in_flight.is_some() {
            return Err(SchemaSessionFailure::InFlight);
        }
        ensure_frontier_slot(&state, shard)?;
        let result = match observer {
            Some(observer) => state.catalog.stage_group_observed(records, observer),
            None => state.catalog.stage_group(records),
        };
        let delta = result.map_err(map_stage_failure)?;
        state.in_flight = Some(identity);
        Ok(delta)
    }
}

fn map_stage_failure(failure: positron_signals::LogStoreFailure) -> SchemaSessionFailure {
    match failure.code() {
        positron_signals::LogStoreFailureCode::Cancelled => SchemaSessionFailure::Cancelled,
        code => SchemaSessionFailure::LogStore(code),
    }
}
