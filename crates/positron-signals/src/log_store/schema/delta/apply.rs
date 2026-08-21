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
        let mut next = self.clone_block_indexes()?;
        if let Some(index) = block_index.as_ref() {
            if next.len() >= MAX_BLOCK_INDEXES {
                return Err(SchemaFailure::LimitExceeded);
            }
            let insertion = match next.binary_search_by_key(&index.identity, |known| known.identity)
            {
                Ok(_) => return Err(SchemaFailure::InvalidValue),
                Err(position) => position,
            };
            next.try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            next.insert(insertion, index.try_clone()?);
        }
        let added_memory = delta
            .retained_memory_bytes
            .checked_sub(delta.physical_memory_bytes())
            .ok_or(SchemaFailure::InvalidValue)?;
        let added_persistent = delta
            .persistent_bytes
            .checked_sub(delta.physical_index_bytes())
            .ok_or(SchemaFailure::InvalidValue)?;
        let added_index = delta
            .index_bytes
            .checked_sub(delta.physical_index_bytes())
            .ok_or(SchemaFailure::InvalidValue)?;
        let new_entries = delta
            .entries
            .iter()
            .filter(|staged| self.entry(&staged.path).is_none())
            .count();
        if self
            .entries
            .len()
            .checked_add(new_entries)
            .is_none_or(|count| count > self.entries.capacity())
        {
            return Err(SchemaFailure::AllocationUnavailable);
        }
        self.replace_block_indexes(next, 0, added_memory, added_persistent, added_index)?;
        for staged in delta.entries {
            self.apply_entry(staged)?;
        }
        self.overflow_records = self.overflow_records.saturating_add(delta.overflow_records);
        self.overflow_bytes = self.overflow_bytes.saturating_add(delta.overflow_bytes);
        Ok(())
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
