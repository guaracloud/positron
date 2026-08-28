use positron_domain::identity::TenantId;
use positron_kernel::{LedgerSnapshot, ResourceGovernor, ResourceReservation, StoreBlockIdentity};
use positron_signals::{ScanCancellation, ScanObservationFailureCode, ScanObserver};

use super::{SchemaSessionFailure, TenantSchemaSession, recovery};

impl TenantSchemaSession {
    /// Runs one eager read against the immutable tenant schema while retaining
    /// the session lock only for the duration of the supplied operation.
    pub fn with_catalog_view<T>(
        &self,
        tenant: TenantId,
        operation: impl FnOnce(&positron_signals::SchemaCatalog) -> T,
    ) -> Result<T, SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.tenant != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        Ok(operation(state.catalog.catalog()))
    }

    #[allow(dead_code)]
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

    pub(crate) fn append_reachable_indexes_observed(
        &self,
        snapshot: &LedgerSnapshot<'_>,
        reachable: &mut Vec<(StoreBlockIdentity, [u8; 32])>,
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        for block in snapshot.blocks() {
            if cancellation.is_cancelled() {
                return Err(SchemaSessionFailure::Cancelled);
            }
            observer.observe_work(1).map_err(|failure| match failure {
                ScanObservationFailureCode::Cancelled => SchemaSessionFailure::Cancelled,
                ScanObservationFailureCode::BudgetExhausted
                | ScanObservationFailureCode::DecodedRecordsExhausted
                | ScanObservationFailureCode::ResourceExhausted
                | ScanObservationFailureCode::Internal => SchemaSessionFailure::StateUnavailable,
            })?;
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
            reachable.insert(position, (block.identity(), digest));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retain_reachable_indexes(
        &self,
        reachable: &[(StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        state
            .catalog
            .retain_reachable_indexes(reachable)
            .map_err(SchemaSessionFailure::Schema)
    }

    pub(crate) fn retain_reachable_indexes_work_units(&self) -> Result<u64, SchemaSessionFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        state
            .catalog
            .retain_reachable_indexes_work_units()
            .map_err(SchemaSessionFailure::Schema)
    }

    pub(crate) fn retain_reachable_indexes_observed(
        &self,
        reachable: &[(StoreBlockIdentity, [u8; 32])],
        cancellation: &dyn ScanCancellation,
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaSessionFailure> {
        if cancellation.is_cancelled() {
            return Err(SchemaSessionFailure::Cancelled);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        state
            .catalog
            .retain_reachable_indexes_observed(reachable, observer)
            .map_err(|failure| match failure {
                positron_signals::SchemaFailure::Observed(
                    ScanObservationFailureCode::Cancelled,
                ) => SchemaSessionFailure::Cancelled,
                positron_signals::SchemaFailure::Observed(_)
                | positron_signals::SchemaFailure::AllocationUnavailable
                | positron_signals::SchemaFailure::LimitExceeded
                | positron_signals::SchemaFailure::InvalidBudget
                | positron_signals::SchemaFailure::InvalidPath
                | positron_signals::SchemaFailure::InvalidValue
                | positron_signals::SchemaFailure::PathTooLong
                | positron_signals::SchemaFailure::MalformedCatalog => {
                    SchemaSessionFailure::Schema(failure)
                },
            })
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
        if !state.catalog.governed_by(governor) {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        if state.in_flight.is_some() || state.pending.is_some() {
            return Err(SchemaSessionFailure::InFlight);
        }
        let original_memory = state.catalog.catalog().memory_bytes();
        let clone_bytes = u64::try_from(state.catalog.catalog().budget().max_memory_bytes())
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        let _clone_capacity = reserve_required_schema_memory(tenant, clone_bytes, governor)?;
        let mut update = state
            .catalog
            .stage_query_update()
            .map_err(SchemaSessionFailure::Schema)?;
        update
            .record_query_use(path)
            .map_err(SchemaSessionFailure::Schema)?;
        for block in snapshot.blocks() {
            let capacity =
                recovery::reserve_query_index_capacity(tenant, block.payload().len(), governor)?;
            update
                .index_replayed_query_path(tenant, snapshot, block, path)
                .map_err(|_| SchemaSessionFailure::ReplayIntegrity)?;
            drop(capacity);
        }
        commit_query_update(&mut state, update, original_memory, governor)?;
        Ok(())
    }

    pub fn remove_query_evidence(
        &self,
        tenant: TenantId,
        path: &positron_signals::SchemaPath,
        governor: ResourceGovernor<'_>,
    ) -> Result<(), SchemaSessionFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        if state.tenant != tenant {
            return Err(SchemaSessionFailure::TenantConflict);
        }
        if !state.catalog.governed_by(governor) {
            return Err(SchemaSessionFailure::StateUnavailable);
        }
        if state.in_flight.is_some() || state.pending.is_some() {
            return Err(SchemaSessionFailure::InFlight);
        }
        let original_memory = state.catalog.catalog().memory_bytes();
        let clone_bytes = u64::try_from(state.catalog.catalog().budget().max_memory_bytes())
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        let _clone_capacity = reserve_required_schema_memory(tenant, clone_bytes, governor)?;
        let mut update = state
            .catalog
            .stage_query_update()
            .map_err(SchemaSessionFailure::Schema)?;
        update
            .remove_query_evidence(path)
            .map_err(SchemaSessionFailure::Schema)?;
        commit_query_update(&mut state, update, original_memory, governor)
    }
}

fn commit_query_update(
    state: &mut super::SessionState,
    update: positron_signals::SchemaQueryUpdate,
    original_memory: usize,
    governor: ResourceGovernor<'_>,
) -> Result<(), SchemaSessionFailure> {
    let next_memory = update.memory_bytes();
    let next_charge = if next_memory >= original_memory {
        state.query_charge_bytes.checked_add(
            u64::try_from(next_memory - original_memory)
                .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?,
        )
    } else {
        Some(
            state.query_charge_bytes.saturating_sub(
                u64::try_from(original_memory - next_memory)
                    .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?,
            ),
        )
    }
    .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    let next_capacity = recovery::reserve_schema_memory(state.tenant, next_charge, governor)?;
    state
        .catalog
        .commit_query_update(update)
        .map_err(SchemaSessionFailure::Schema)?;
    state.query_capacity = next_capacity.map(ResourceReservation::transfer);
    state.query_charge_bytes = next_charge;
    Ok(())
}

fn reserve_required_schema_memory<'authority>(
    tenant: TenantId,
    bytes: u64,
    governor: ResourceGovernor<'authority>,
) -> Result<positron_kernel::ResourceReservation<'authority>, SchemaSessionFailure> {
    recovery::reserve_schema_memory(tenant, bytes, governor)?
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)
}
