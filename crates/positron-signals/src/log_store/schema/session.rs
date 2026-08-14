use positron_domain::identity::TenantId;
use positron_domain::value::AttributeOccurrenceSet;
use positron_kernel::{CommittedBlock, LedgerSnapshot, StoreBlockIdentity};

use super::{SchemaBudget, SchemaCatalog, SchemaDelta, SchemaFailure, SchemaObservation};
use crate::log_store::{LogRecord, LogStore, LogStoreFailure};

/// Tenant-bound mutable schema authority owned by the governed ingest session.
pub struct TenantSchemaState {
    catalog: SchemaCatalog,
}

impl TenantSchemaState {
    pub fn new(tenant: TenantId, budget: SchemaBudget) -> Result<Self, SchemaFailure> {
        SchemaCatalog::new(tenant, budget).map(|catalog| Self { catalog })
    }

    #[must_use]
    pub fn from_catalog(catalog: SchemaCatalog) -> Self {
        Self { catalog }
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.catalog.tenant()
    }

    #[must_use]
    pub const fn catalog(&self) -> &SchemaCatalog {
        &self.catalog
    }

    pub fn stage_group(&self, records: &mut [LogRecord]) -> Result<SchemaDelta, LogStoreFailure> {
        LogStore::new().stage_schema_group(records, &self.catalog)
    }

    /// Observes validated values through the tenant-bound authority.
    pub fn observe(
        &mut self,
        attributes: &[AttributeOccurrenceSet],
    ) -> Result<SchemaObservation, SchemaFailure> {
        let mut delta = SchemaDelta::empty(self.tenant(), false);
        let observation = self.catalog.stage_record(
            attributes,
            &mut delta,
            &mut super::delta::DiscoveryMeter::new(),
        )?;
        self.catalog.apply_delta(delta, None)?;
        Ok(observation)
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
}
