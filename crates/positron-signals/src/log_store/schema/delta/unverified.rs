use super::SchemaDelta;
use crate::log_store::schema::catalog::SchemaCatalog;
use crate::log_store::schema::failure::SchemaFailure;
use crate::log_store::schema::index::{BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES};
use crate::log_store::schema::model::{SchemaBudget, SchemaEntry, SchemaPath};

impl SchemaDelta {
    pub(super) fn path_is_unverified(&self, path: &SchemaPath) -> bool {
        self.unverified_paths.iter().any(|known| known == path)
    }

    pub(super) fn mark_paths_unverified(
        &mut self,
        catalog: &SchemaCatalog,
        root: &[SchemaEntry],
    ) -> Result<(), SchemaFailure> {
        for entry in root
            .iter()
            .filter(|entry| entry.query_uses > 0 && entry.promoted)
        {
            if !self.path_is_unverified(&entry.path) {
                self.unverified_paths
                    .try_reserve_exact(1)
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                self.unverified_paths.push(entry.path.try_clone()?);
            }
        }

        let had_index_paths = !self.index_paths.is_empty();
        let mut position = self.index_paths.len();
        while position > 0 {
            position -= 1;
            let remove = self
                .index_paths
                .get(position)
                .is_some_and(|indexed| root.iter().any(|entry| entry.path == indexed.path));
            if !remove {
                continue;
            }
            let indexed = self
                .index_paths
                .get(position)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.physical_index_bytes = self
                .physical_index_bytes
                .checked_sub(indexed.encoded_bytes()?)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.physical_memory_bytes = self
                .physical_memory_bytes
                .checked_sub(indexed.memory_bytes()?)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.index_paths.remove(position);
        }
        if had_index_paths && self.index_paths.is_empty() {
            let index_header = if catalog.block_indexes.is_empty() {
                INDEX_HEADER_BYTES
            } else {
                0
            };
            self.physical_index_bytes = self
                .physical_index_bytes
                .checked_sub(BLOCK_INDEX_HEADER_BYTES + index_header)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.physical_memory_bytes = self
                .physical_memory_bytes
                .checked_sub(SchemaBudget::block_index_memory_bytes())
                .ok_or(SchemaFailure::InvalidValue)?;
        }
        Ok(())
    }
}
