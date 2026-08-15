use positron_domain::identity::TenantId;
use positron_kernel::{
    CommittedBlock, LedgerSnapshot, ResourceGovernor, ResourceReservation, StoreBlockIdentity,
    TransferredResourceReservation,
};

use super::{SchemaBudget, SchemaCatalog, SchemaDelta, SchemaFailure};
use crate::log_store::{LogRecord, LogStore, LogStoreFailure};

/// Opaque tenant-bound schema store owned by the governed ingest session.
///
/// Construction consumes the live governor grant, so mutable authority cannot
/// outlive or be copied independently from its capacity.
#[doc(hidden)]
pub struct SchemaSessionStore {
    catalog: SchemaCatalog,
    _capacity: TransferredResourceReservation,
    capacity_bytes: u64,
}

impl SchemaSessionStore {
    pub fn new(
        reservation: ResourceReservation<'_>,
        tenant: TenantId,
        budget: SchemaBudget,
    ) -> Result<Self, SchemaFailure> {
        let memory_bytes = u64::try_from(SchemaCatalog::base_memory_bound(budget)?)
            .map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(tenant, memory_bytes) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        let capacity_bytes = reservation
            .granted()
            .get(positron_kernel::ResourceDimension::MemoryBytes);
        let catalog = SchemaCatalog::new(tenant, budget)?;
        Ok(Self {
            catalog,
            _capacity: reservation.transfer(),
            capacity_bytes,
        })
    }

    pub fn from_checkpoint(
        reservation: ResourceReservation<'_>,
        tenant: TenantId,
        checkpoint: &[u8],
    ) -> Result<Option<(Self, Vec<super::SchemaCheckpointFrontier>)>, SchemaFailure> {
        let memory_bytes = u64::try_from(SchemaCatalog::catalog_memory_bound(checkpoint)?)
            .map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(tenant, memory_bytes) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        let capacity_bytes = reservation
            .granted()
            .get(positron_kernel::ResourceDimension::MemoryBytes);
        let (catalog, frontiers) = SchemaCatalog::decode_checkpoint_object(checkpoint)?;
        if catalog.tenant() != tenant {
            return Ok(None);
        }
        Ok(Some((
            Self {
                catalog,
                _capacity: reservation.transfer(),
                capacity_bytes,
            },
            frontiers,
        )))
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.catalog.tenant()
    }

    #[must_use]
    pub const fn catalog(&self) -> &SchemaCatalog {
        &self.catalog
    }

    #[must_use]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    #[must_use]
    pub fn governed_by(&self, governor: ResourceGovernor<'_>) -> bool {
        self._capacity.can_reclaim_with(governor)
    }

    pub fn stage_group(&self, records: &mut [LogRecord]) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().stage_schema_group(records, &self.catalog)
    }

    pub fn commit(
        &mut self,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), LogStoreFailure> {
        LogStore::new().apply_schema_delta(&mut self.catalog, delta, identity, digest)
    }

    pub fn replay(
        &self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().replay_schema_block(tenant, snapshot, block, &self.catalog)
    }

    pub fn record_query_use(&mut self, path: &super::SchemaPath) -> Result<(), SchemaFailure> {
        self.catalog.record_query_use(path)
    }

    pub fn index_replayed_query_path(
        &mut self,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        path: &super::SchemaPath,
    ) -> Result<(), LogStoreFailure> {
        let delta = LogStore::new().replay_schema_block(tenant, snapshot, block, &self.catalog)?;
        let digest = block.content_digest().map_err(LogStoreFailure::kernel)?;
        if let Some(index) = delta
            .into_query_index(path, block.identity(), digest)
            .map_err(crate::log_store::map_schema_failure)?
        {
            self.catalog
                .install_query_index(index)
                .map_err(crate::log_store::map_schema_failure)?;
        }
        Ok(())
    }

    pub fn remove_query_evidence(&mut self, path: &super::SchemaPath) -> Result<(), SchemaFailure> {
        self.catalog.remove_query_evidence(path)
    }

    pub fn has_verified_block(&self, identity: StoreBlockIdentity, digest: [u8; 32]) -> bool {
        self.catalog.has_verified_block(identity, digest)
    }

    pub fn reconcile_block_identity(
        &mut self,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), SchemaFailure> {
        self.catalog.reconcile_block_identity(identity, digest)
    }

    pub fn retain_reachable_indexes(
        &mut self,
        reachable: &[(StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaFailure> {
        self.catalog.retain_reachable_indexes(reachable)
    }
}
