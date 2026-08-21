use positron_domain::identity::TenantId;
#[cfg(test)]
use positron_domain::value::AttributeOccurrenceSet;

#[cfg(test)]
use super::delta::{DiscoveryMeter, SchemaDelta};
use super::failure::SchemaFailure;
use super::index::SchemaBlockIndex;
use super::model::{
    CATALOG_HEADER_BYTES, SchemaBudget, SchemaEntry, SchemaPath, catalog_base_memory_bytes,
};
#[cfg(test)]
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
    pub(crate) block_indexes: Vec<SchemaBlockIndex>,
}

impl SchemaCatalog {
    pub fn base_memory_bound(budget: SchemaBudget) -> Result<usize, SchemaFailure> {
        catalog_base_memory_bytes(budget.max_entries())
            .filter(|bytes| *bytes <= budget.max_memory_bytes())
            .ok_or(SchemaFailure::InvalidBudget)
    }

    pub fn new(tenant: TenantId, budget: SchemaBudget) -> Result<Self, SchemaFailure> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(budget.max_entries())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        let memory_bytes = Self::base_memory_bound(budget)?;
        Ok(Self {
            tenant,
            budget,
            entries,
            memory_bytes,
            persistent_bytes: CATALOG_HEADER_BYTES,
            index_bytes: 0,
            overflow_records: 0,
            overflow_bytes: 0,
            block_indexes: Vec::new(),
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

    #[cfg(test)]
    pub(crate) fn verified_block_kind(
        &self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
        path: &SchemaPath,
        kind: positron_domain::value::AttributeValueKind,
    ) -> Option<bool> {
        self.verified_block(identity, digest)
            .and_then(|index| index.covers_kind(path, kind))
    }

    fn verified_block(
        &self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Option<&SchemaBlockIndex> {
        self.block_indexes
            .binary_search_by_key(&identity, |index| index.identity)
            .ok()
            .and_then(|position| self.block_indexes.get(position))
            .filter(|index| index.digest == digest)
            .filter(|index| index.semantically_valid(&self.entries))
    }

    pub(crate) fn has_verified_block(
        &self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
    ) -> bool {
        self.verified_block(identity, digest).is_some()
    }

    pub(crate) fn entry_index(&self, path: &SchemaPath) -> Result<usize, usize> {
        self.entries.binary_search_by(|entry| entry.path.cmp(path))
    }

    pub(crate) fn clone_block_indexes(&self) -> Result<Vec<SchemaBlockIndex>, SchemaFailure> {
        let mut next = Vec::new();
        next.try_reserve_exact(self.block_indexes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for block in &self.block_indexes {
            next.push(block.try_clone()?);
        }
        Ok(next)
    }

    pub(crate) fn replace_block_indexes(
        &mut self,
        mut next: Vec<SchemaBlockIndex>,
        entry_index_reduction: usize,
        added_memory: usize,
        added_persistent: usize,
        added_index: usize,
    ) -> Result<(), SchemaFailure> {
        for block in &mut next {
            block.scalar_framing = block.scalar_framing.for_mutation();
        }
        let old_wire = Self::block_indexes_wire(&self.block_indexes)?;
        let new_wire = Self::block_indexes_wire(&next)?;
        let old_memory = Self::block_indexes_memory(&self.block_indexes)?;
        let new_memory = Self::block_indexes_memory(&next)?;
        let next_persistent = self
            .persistent_bytes
            .checked_sub(old_wire)
            .and_then(|bytes| bytes.checked_add(new_wire))
            .and_then(|bytes| bytes.checked_add(added_persistent))
            .ok_or(SchemaFailure::InvalidValue)?;
        let next_index = self
            .index_bytes
            .checked_sub(old_wire)
            .and_then(|bytes| bytes.checked_add(new_wire))
            .and_then(|bytes| bytes.checked_add(added_index))
            .and_then(|bytes| bytes.checked_sub(entry_index_reduction))
            .ok_or(SchemaFailure::InvalidValue)?;
        let next_memory = self
            .memory_bytes
            .checked_sub(old_memory)
            .and_then(|bytes| bytes.checked_add(new_memory))
            .and_then(|bytes| bytes.checked_add(added_memory))
            .ok_or(SchemaFailure::InvalidValue)?;
        if next_persistent > self.budget.max_persistent_bytes()
            || next_index > self.budget.max_index_bytes()
            || next_memory > self.budget.max_memory_bytes()
        {
            return Err(SchemaFailure::LimitExceeded);
        }
        self.block_indexes = next;
        self.persistent_bytes = next_persistent;
        self.index_bytes = next_index;
        self.memory_bytes = next_memory;
        Ok(())
    }

    fn block_indexes_wire(blocks: &[SchemaBlockIndex]) -> Result<usize, SchemaFailure> {
        if blocks.is_empty() {
            return Ok(0);
        }
        blocks
            .iter()
            .try_fold(super::index::INDEX_HEADER_BYTES, |total, block| {
                total
                    .checked_add(block.encoded_bytes()?)
                    .ok_or(SchemaFailure::LimitExceeded)
            })
    }

    fn block_indexes_memory(blocks: &[SchemaBlockIndex]) -> Result<usize, SchemaFailure> {
        blocks.iter().try_fold(0_usize, |total, block| {
            let paths = block.paths.iter().try_fold(
                SchemaBudget::block_index_memory_bytes(),
                |memory, path| {
                    memory
                        .checked_add(path.memory_bytes()?)
                        .ok_or(SchemaFailure::LimitExceeded)
                },
            )?;
            total.checked_add(paths).ok_or(SchemaFailure::LimitExceeded)
        })
    }

    /// Observes one record's already validated occurrence sets.
    #[cfg(test)]
    pub(crate) fn observe(
        &mut self,
        attributes: &[AttributeOccurrenceSet],
    ) -> Result<SchemaObservation, SchemaFailure> {
        let mut delta = SchemaDelta::empty(self.tenant, false);
        let observation = self.stage_record(attributes, &mut delta, &mut DiscoveryMeter::new())?;
        self.apply_delta(delta, None)?;
        Ok(observation)
    }
}
