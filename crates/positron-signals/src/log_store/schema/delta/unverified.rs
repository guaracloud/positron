use positron_domain::value::{AttributeOccurrenceSet, ValidatedAttributeValue};

use super::{DiscoveryMeter, SchemaDelta, projected_cost, staged_memory_bytes};
use crate::log_store::schema::catalog::SchemaCatalog;
use crate::log_store::schema::failure::SchemaFailure;
use crate::log_store::schema::index::{
    BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, SchemaBlockIndex,
};
use crate::log_store::schema::model::{SchemaBudget, SchemaEntry, SchemaPath};

impl SchemaDelta {
    pub(super) fn path_is_unverified(&self, path: &SchemaPath) -> bool {
        self.all_paths_unverified || self.unverified_paths.iter().any(|known| known == path)
    }

    pub(super) fn mark_paths_unverified(
        &mut self,
        catalog: &SchemaCatalog,
        root: &[SchemaEntry],
    ) -> Result<(), SchemaFailure> {
        for entry in catalog.entries().filter(|entry| {
            entry.query_uses > 0
                && entry.promoted
                && root.iter().any(|observed| {
                    observed.path.namespace() == entry.path.namespace()
                        && observed.path.segments().first() == entry.path.segments().first()
                })
        }) {
            self.mark_path_unverified(catalog, &entry.path)?;
        }

        Ok(())
    }

    pub(super) fn mark_overflow_paths(
        &mut self,
        catalog: &SchemaCatalog,
        set: &AttributeOccurrenceSet,
        meter: &mut DiscoveryMeter,
    ) -> Result<(), SchemaFailure> {
        let root = SchemaPath::root_borrowed(set.namespace(), set.key())?;
        for index in 0..set.len() {
            let value = set.occurrence(index).ok_or(SchemaFailure::InvalidValue)?;
            if !self.mark_overflow_value(catalog, &root, value, meter)? {
                break;
            }
        }
        Ok(())
    }

    fn mark_overflow_value(
        &mut self,
        catalog: &SchemaCatalog,
        path: &SchemaPath,
        value: &ValidatedAttributeValue,
        meter: &mut DiscoveryMeter,
    ) -> Result<bool, SchemaFailure> {
        self.mark_path_unverified(catalog, path)?;
        let Some(count) = value.key_value_list_len() else {
            return Ok(true);
        };
        for index in 0..count {
            if !meter.consume()? {
                self.mark_all_paths_unverified(catalog)?;
                return Ok(false);
            }
            let entry = value
                .key_value_entry(index)
                .ok_or(SchemaFailure::InvalidValue)?;
            let Some(child) = path.child(entry.key())? else {
                continue;
            };
            if !self.mark_overflow_value(catalog, &child, entry.value(), meter)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn mark_all_paths_unverified(&mut self, catalog: &SchemaCatalog) -> Result<(), SchemaFailure> {
        self.all_paths_unverified = true;
        self.index_paths = Vec::new();
        self.unverified_paths = Vec::new();
        self.physical_index_bytes = 0;
        self.physical_memory_bytes = 0;
        let (memory, persistent, index, _) = projected_cost(catalog, self, None)?;
        self.retained_memory_bytes = memory;
        self.persistent_bytes = persistent;
        self.index_bytes = index;
        self.staged_memory_bytes = staged_memory_bytes(self)?;
        Ok(())
    }

    fn mark_path_unverified(
        &mut self,
        catalog: &SchemaCatalog,
        path: &SchemaPath,
    ) -> Result<(), SchemaFailure> {
        if !catalog
            .entry(path)
            .is_some_and(|entry| entry.query_uses() > 0 && entry.promoted())
        {
            return Ok(());
        }
        if !self.path_is_unverified(path) {
            self.unverified_paths
                .try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            self.unverified_paths.push(path.try_clone()?);
        }

        let mut removed = false;
        let old_wire = SchemaBlockIndex::paths_encoded_bytes(&self.index_paths)?;
        let mut position = self.index_paths.len();
        while position > 0 {
            position -= 1;
            let remove = self
                .index_paths
                .get(position)
                .is_some_and(|indexed| indexed.path == *path);
            if !remove {
                continue;
            }
            removed = true;
            let indexed = self
                .index_paths
                .get(position)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.physical_memory_bytes = self
                .physical_memory_bytes
                .checked_sub(indexed.memory_bytes()?)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.index_paths.remove(position);
        }
        if removed {
            if self.index_paths.is_empty() {
                let index_header = if catalog.block_indexes.is_empty() {
                    INDEX_HEADER_BYTES
                } else {
                    0
                };
                self.physical_index_bytes = self
                    .physical_index_bytes
                    .checked_sub(old_wire)
                    .and_then(|bytes| bytes.checked_sub(BLOCK_INDEX_HEADER_BYTES))
                    .and_then(|bytes| bytes.checked_sub(index_header))
                    .ok_or(SchemaFailure::InvalidValue)?;
            } else {
                let new_wire = SchemaBlockIndex::paths_encoded_bytes(&self.index_paths)?;
                self.physical_index_bytes = self
                    .physical_index_bytes
                    .checked_sub(
                        old_wire
                            .checked_sub(new_wire)
                            .ok_or(SchemaFailure::InvalidValue)?,
                    )
                    .ok_or(SchemaFailure::InvalidValue)?;
            }
        }
        if removed && self.index_paths.is_empty() {
            self.physical_memory_bytes = self
                .physical_memory_bytes
                .checked_sub(SchemaBudget::block_index_memory_bytes())
                .ok_or(SchemaFailure::InvalidValue)?;
        }
        Ok(())
    }
}
