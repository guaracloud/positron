use positron_domain::identity::TenantId;
use positron_domain::value::AttributeOccurrenceSet;

use super::delta::{DiscoveryMeter, SchemaDelta};
use super::failure::SchemaFailure;
use super::model::{
    CATALOG_HEADER_BYTES, SchemaBudget, SchemaEntry, SchemaPath, catalog_base_memory_bytes,
};
use super::observation::SchemaObservation;

/// Observable typed schema and overflow state for one tenant.
#[derive(Debug, Eq, PartialEq)]
pub struct SchemaCatalog {
    pub(crate) tenant: TenantId,
    pub(crate) budget: SchemaBudget,
    pub(crate) entries: Vec<SchemaEntry>,
    pub(crate) memory_bytes: usize,
    pub(crate) persistent_bytes: usize,
    pub(crate) index_bytes: usize,
    pub(crate) overflow_records: u64,
    pub(crate) overflow_bytes: u64,
}

impl SchemaCatalog {
    pub fn new(tenant: TenantId, budget: SchemaBudget) -> Result<Self, SchemaFailure> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(budget.max_entries())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        let memory_bytes = catalog_base_memory_bytes(entries.capacity())
            .filter(|bytes| *bytes <= budget.max_memory_bytes())
            .ok_or(SchemaFailure::InvalidBudget)?;
        Ok(Self {
            tenant,
            budget,
            entries,
            memory_bytes,
            persistent_bytes: CATALOG_HEADER_BYTES,
            index_bytes: 0,
            overflow_records: 0,
            overflow_bytes: 0,
        })
    }

    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub const fn budget(&self) -> SchemaBudget {
        self.budget
    }

    #[must_use]
    pub fn entry(&self, path: &SchemaPath) -> Option<&SchemaEntry> {
        self.entry_index(path)
            .ok()
            .and_then(|index| self.entries.get(index))
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    #[must_use]
    pub const fn persistent_bytes(&self) -> usize {
        self.persistent_bytes
    }

    #[must_use]
    pub const fn index_bytes(&self) -> usize {
        self.index_bytes
    }

    #[must_use]
    pub const fn overflow_record_count(&self) -> u64 {
        self.overflow_records
    }

    #[must_use]
    pub const fn overflow_byte_count(&self) -> u64 {
        self.overflow_bytes
    }

    pub fn entries(&self) -> impl Iterator<Item = &SchemaEntry> {
        self.entries.iter()
    }

    fn entry_index(&self, path: &SchemaPath) -> Result<usize, usize> {
        self.entries.binary_search_by(|entry| entry.path.cmp(path))
    }

    /// Observes one record's already validated occurrence sets.
    pub fn observe(
        &mut self,
        attributes: &[AttributeOccurrenceSet],
    ) -> Result<SchemaObservation, SchemaFailure> {
        let mut delta = SchemaDelta::empty();
        let observation = self.stage_record(attributes, &mut delta, &mut DiscoveryMeter::new())?;
        self.apply_delta(delta)?;
        Ok(observation)
    }
}
