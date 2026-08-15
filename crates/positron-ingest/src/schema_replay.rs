use positron_domain::identity::TenantId;
use positron_kernel::StoreBlockIdentity;
use positron_kernel::{
    LedgerSnapshot, RecoveryAuthority, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts,
    ResourceReservation,
};
use positron_signals::SchemaBudget;

use crate::{SchemaSessionFailure, TenantSchemaCheckpoint, TenantSchemaSession};

/// Bounded bootstrap-only schema reconstruction without a serving lifetime reservation.
pub struct SchemaReplayBuilder<'authority> {
    tenant: TenantId,
    session: TenantSchemaSession,
    source_bytes: u64,
    recovery: ResourceReservation<'authority>,
    reachable_indexes: Vec<(StoreBlockIdentity, [u8; 32])>,
}

impl<'authority> SchemaReplayBuilder<'authority> {
    pub fn new(
        tenant: TenantId,
        checkpoint: Option<&[u8]>,
        recovery: RecoveryAuthority<'authority>,
    ) -> Result<Self, SchemaSessionFailure> {
        let source_bytes = u64::try_from(checkpoint.map_or(0, <[u8]>::len))
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        let peak = peak_resources(source_bytes)?;
        let claim = RecoveryWorkClaim::tenant(tenant, RecoveryWorkKind::Repair, peak)
            .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        let base_bytes = match checkpoint {
            Some(bytes) => TenantSchemaSession::checkpoint_construction_memory_bytes(bytes)?,
            None => TenantSchemaSession::release_1_base_memory_bytes()?,
        };
        let base_claim = RecoveryWorkClaim::tenant(
            tenant,
            RecoveryWorkKind::Repair,
            active_resources(base_bytes)?,
        )
        .map_err(|_| SchemaSessionFailure::ReplayLimitExceeded)?;
        let base_capacity = recovery
            .reserve(base_claim)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        let recovery = recovery
            .reserve(claim)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        let session = match checkpoint {
            Some(bytes) => TenantSchemaSession::from_checkpoint(tenant, bytes, base_capacity)?,
            None => TenantSchemaSession::release_1(tenant, base_capacity)?,
        };
        let mut reachable_indexes = Vec::new();
        reachable_indexes
            .try_reserve_exact(SchemaBudget::system_max_entries())
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        Ok(Self {
            tenant,
            session,
            source_bytes,
            recovery,
            reachable_indexes,
        })
    }

    pub fn replay_snapshot(
        &mut self,
        snapshot: &LedgerSnapshot<'_>,
    ) -> Result<(), SchemaSessionFailure> {
        self.recovery
            .try_resize(peak_resources(self.source_bytes)?)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        self.session
            .replay_snapshot_for_bootstrap(self.tenant, snapshot, &mut self.recovery)?;
        self.session
            .append_reachable_indexes(snapshot, &mut self.reachable_indexes)?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<TenantSchemaCheckpoint, SchemaSessionFailure> {
        self.recovery
            .try_resize(peak_resources(self.source_bytes)?)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        self.session
            .retain_reachable_indexes(&self.reachable_indexes)?;
        self.session.checkpoint()
    }
}

fn peak_resources(source_bytes: u64) -> Result<ResourceAmounts, SchemaSessionFailure> {
    let working = SchemaBudget::replay_working_memory_bytes(1_048_576)
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    let reachable = SchemaBudget::system_max_entries()
        .checked_mul(std::mem::size_of::<(StoreBlockIdentity, [u8; 32])>())
        .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    let serialized = SchemaBudget::release_1()
        .map_err(SchemaSessionFailure::Schema)?
        .max_persistent_bytes();
    let memory = u64::try_from(
        working
            .checked_add(reachable)
            .and_then(|bytes| bytes.checked_add(serialized))
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?,
    )
    .ok()
    .and_then(|bytes| bytes.checked_add(source_bytes))
    .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
    active_resources(memory)
}

fn active_resources(memory: u64) -> Result<ResourceAmounts, SchemaSessionFailure> {
    Ok(ResourceAmounts::new([
        memory.max(1),
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
        0,
        0,
    ]))
}

#[cfg(test)]
#[path = "schema_replay/tests/mod.rs"]
mod tests;
