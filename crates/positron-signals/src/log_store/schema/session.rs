use positron_domain::identity::TenantId;
use positron_kernel::{CommittedBlock, LedgerSnapshot, ResourceReservation, StoreBlockIdentity};

use super::{SchemaBudget, SchemaCatalog, SchemaDelta, SchemaFailure};
use crate::log_store::{LogRecord, LogStore, LogStoreFailure};

/// Tenant-bound mutable schema authority owned by the governed ingest session.
pub struct TenantSchemaState {
    catalog: SchemaCatalog,
}

/// Opaque proof that mutable schema state is owned by a live governed tenant session.
#[derive(Clone, Copy)]
pub struct SchemaMutationPermit {
    tenant: TenantId,
    _private: (),
}

impl SchemaMutationPermit {
    pub fn for_new_catalog(
        reservation: &ResourceReservation<'_>,
        tenant: TenantId,
        budget: SchemaBudget,
    ) -> Result<Self, SchemaFailure> {
        let memory_bytes = u64::try_from(SchemaCatalog::base_memory_bound(budget)?)
            .map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(tenant, memory_bytes) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        Ok(Self {
            tenant,
            _private: (),
        })
    }

    pub fn for_checkpoint(
        reservation: &ResourceReservation<'_>,
        tenant: TenantId,
        checkpoint: &[u8],
    ) -> Result<Self, SchemaFailure> {
        let memory_bytes = u64::try_from(SchemaCatalog::catalog_memory_bound(checkpoint)?)
            .map_err(|_| SchemaFailure::LimitExceeded)?;
        if !reservation.authorizes_tenant_schema_session(tenant, memory_bytes) {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        Ok(Self {
            tenant,
            _private: (),
        })
    }

    fn authorize(&self, tenant: TenantId) -> Result<(), SchemaFailure> {
        if self.tenant == tenant {
            Ok(())
        } else {
            Err(SchemaFailure::InvalidValue)
        }
    }
}

impl TenantSchemaState {
    pub fn new(
        permit: &SchemaMutationPermit,
        tenant: TenantId,
        budget: SchemaBudget,
    ) -> Result<Self, SchemaFailure> {
        permit.authorize(tenant)?;
        SchemaCatalog::new(tenant, budget).map(|catalog| Self { catalog })
    }

    pub fn from_catalog(
        permit: &SchemaMutationPermit,
        catalog: SchemaCatalog,
    ) -> Result<Self, SchemaFailure> {
        permit.authorize(catalog.tenant())?;
        Ok(Self { catalog })
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.catalog.tenant()
    }

    #[must_use]
    pub const fn catalog(&self) -> &SchemaCatalog {
        &self.catalog
    }

    pub fn stage_group(
        &self,
        permit: &SchemaMutationPermit,
        records: &mut [LogRecord],
    ) -> Result<SchemaDelta, LogStoreFailure> {
        permit
            .authorize(self.tenant())
            .map_err(crate::log_store::map_schema_failure)?;
        LogStore::new().stage_schema_group(records, &self.catalog)
    }

    pub fn commit(
        &mut self,
        permit: &SchemaMutationPermit,
        delta: SchemaDelta,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), LogStoreFailure> {
        permit
            .authorize(self.tenant())
            .map_err(crate::log_store::map_schema_failure)?;
        LogStore::new().apply_schema_delta(&mut self.catalog, delta, identity, digest)
    }

    pub fn replay(
        &self,
        permit: &SchemaMutationPermit,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
    ) -> Result<SchemaDelta, LogStoreFailure> {
        permit
            .authorize(self.tenant())
            .map_err(crate::log_store::map_schema_failure)?;
        LogStore::new().replay_schema_block(tenant, snapshot, block, &self.catalog)
    }

    pub fn record_query_use(
        &mut self,
        permit: &SchemaMutationPermit,
        path: &super::SchemaPath,
    ) -> Result<(), SchemaFailure> {
        permit.authorize(self.tenant())?;
        self.catalog.record_query_use(path)
    }

    pub fn index_replayed_query_path(
        &mut self,
        permit: &SchemaMutationPermit,
        tenant: TenantId,
        snapshot: &LedgerSnapshot<'_>,
        block: &CommittedBlock,
        path: &super::SchemaPath,
    ) -> Result<(), LogStoreFailure> {
        permit
            .authorize(self.tenant())
            .map_err(crate::log_store::map_schema_failure)?;
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

    pub fn remove_query_evidence(
        &mut self,
        permit: &SchemaMutationPermit,
        path: &super::SchemaPath,
    ) -> Result<(), SchemaFailure> {
        permit.authorize(self.tenant())?;
        self.catalog.remove_query_evidence(path)
    }

    pub fn has_verified_block(&self, identity: StoreBlockIdentity, digest: [u8; 32]) -> bool {
        self.catalog.has_verified_block(identity, digest)
    }

    pub fn reconcile_block_identity(
        &mut self,
        permit: &SchemaMutationPermit,
        identity: StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), SchemaFailure> {
        permit.authorize(self.tenant())?;
        self.catalog.reconcile_block_identity(identity, digest)
    }

    pub fn retain_reachable_indexes(
        &mut self,
        permit: &SchemaMutationPermit,
        reachable: &[(StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaFailure> {
        permit.authorize(self.tenant())?;
        self.catalog.retain_reachable_indexes(reachable)
    }
}
