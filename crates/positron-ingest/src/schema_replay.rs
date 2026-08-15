use positron_domain::identity::TenantId;
use positron_kernel::StoreBlockIdentity;
use positron_kernel::{
    LedgerSnapshot, RecoveryAuthority, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts,
    ResourceReservation,
};
use positron_signals::SchemaBudget;
use positron_signals::SchemaMutationPermit;

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
        let recovery = recovery
            .reserve(claim)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        let permit = match checkpoint {
            Some(bytes) => SchemaMutationPermit::for_checkpoint(&recovery, tenant, bytes),
            None => SchemaMutationPermit::for_new_catalog(
                &recovery,
                tenant,
                SchemaBudget::release_1().map_err(SchemaSessionFailure::Schema)?,
            ),
        }
        .map_err(SchemaSessionFailure::Schema)?;
        let session = match checkpoint {
            Some(bytes) => TenantSchemaSession::from_checkpoint(tenant, bytes, permit)?,
            None => TenantSchemaSession::release_1(tenant, permit)?,
        };
        Ok(Self {
            tenant,
            session,
            source_bytes,
            recovery,
            reachable_indexes: Vec::new(),
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
        let retained = self
            .session
            .base_memory_bytes()?
            .checked_add(self.source_bytes)
            .ok_or(SchemaSessionFailure::ReplayLimitExceeded)?;
        self.recovery
            .try_resize(active_resources(retained)?)
            .map_err(|_| SchemaSessionFailure::StateUnavailable)?;
        Ok(())
    }

    pub fn finish(self) -> Result<TenantSchemaCheckpoint, SchemaSessionFailure> {
        self.session
            .retain_reachable_indexes(&self.reachable_indexes)?;
        self.session.checkpoint()
    }
}

fn peak_resources(source_bytes: u64) -> Result<ResourceAmounts, SchemaSessionFailure> {
    let memory = u64::try_from(
        SchemaBudget::replay_working_memory_bytes(1_048_576)
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
