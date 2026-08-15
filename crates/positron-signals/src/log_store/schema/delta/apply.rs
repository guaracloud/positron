use super::SchemaDelta;
use crate::log_store::schema::catalog::SchemaCatalog;
use crate::log_store::schema::failure::SchemaFailure;
use crate::log_store::schema::index::{MAX_BLOCK_INDEXES, SchemaBlockIndex};

impl SchemaCatalog {
    pub(crate) fn apply_delta(
        &mut self,
        delta: SchemaDelta,
        block_index: Option<SchemaBlockIndex>,
    ) -> Result<(), SchemaFailure> {
        if delta.tenant != self.tenant {
            return Err(SchemaFailure::InvalidValue);
        }
        if block_index.as_ref().is_some_and(|index| {
            !index.semantically_valid_with_delta(&self.entries, &delta.entries)
        }) {
            return Err(SchemaFailure::InvalidValue);
        }
        if block_index.as_ref().is_some_and(|index| {
            self.block_indexes
                .binary_search_by_key(&index.identity, |known| known.identity)
                .ok()
                .and_then(|position| self.block_indexes.get(position))
                == Some(index)
        }) {
            return Ok(());
        }
        let insertion = self.prepare_block_index(block_index.as_ref())?;
        let memory_bytes = self
            .memory_bytes
            .checked_add(delta.retained_memory_bytes)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let persistent_bytes = self
            .persistent_bytes
            .checked_add(delta.persistent_bytes)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let index_bytes = self
            .index_bytes
            .checked_add(delta.index_bytes)
            .ok_or(SchemaFailure::LimitExceeded)?;
        for staged in delta.entries {
            self.apply_entry(staged)?;
        }
        self.memory_bytes = memory_bytes;
        self.persistent_bytes = persistent_bytes;
        self.index_bytes = index_bytes;
        self.overflow_records = self.overflow_records.saturating_add(delta.overflow_records);
        self.overflow_bytes = self.overflow_bytes.saturating_add(delta.overflow_bytes);
        if let Some(index) = block_index {
            self.block_indexes
                .insert(insertion.ok_or(SchemaFailure::InvalidValue)?, index);
        }
        Ok(())
    }

    fn prepare_block_index(
        &mut self,
        index: Option<&SchemaBlockIndex>,
    ) -> Result<Option<usize>, SchemaFailure> {
        let Some(index) = index else {
            return Ok(None);
        };
        match self
            .block_indexes
            .binary_search_by_key(&index.identity, |known| known.identity)
        {
            Ok(_) => Err(SchemaFailure::InvalidValue),
            Err(position) => {
                if self.block_indexes.len() >= MAX_BLOCK_INDEXES {
                    return Err(SchemaFailure::LimitExceeded);
                }
                self.block_indexes
                    .try_reserve_exact(1)
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                Ok(Some(position))
            },
        }
    }

    fn apply_entry(
        &mut self,
        staged: crate::log_store::schema::SchemaEntry,
    ) -> Result<(), SchemaFailure> {
        match self
            .entries
            .binary_search_by(|entry| entry.path.cmp(&staged.path))
        {
            Ok(index) => {
                let entry = self
                    .entries
                    .get_mut(index)
                    .ok_or(SchemaFailure::InvalidValue)?;
                *entry = staged;
            },
            Err(index) => {
                if self.entries.len() == self.entries.capacity() {
                    return Err(SchemaFailure::AllocationUnavailable);
                }
                self.entries.insert(index, staged);
            },
        }
        Ok(())
    }
}
