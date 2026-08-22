use super::SchemaDelta;
use crate::log_store::ScanObserver;
use crate::log_store::schema::catalog::SchemaCatalog;
use crate::log_store::schema::failure::SchemaFailure;
use crate::log_store::schema::index::{MAX_BLOCK_INDEXES, SchemaBlockIndex};

impl SchemaCatalog {
    pub(crate) fn apply_replay_delta(
        &mut self,
        delta: SchemaDelta,
        block_index: Option<SchemaBlockIndex>,
        observer: &dyn ScanObserver,
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
        let persistent = self
            .persistent_bytes
            .checked_add(delta.physical_index_bytes())
            .and_then(|bytes| bytes.checked_add(added_persistent))
            .ok_or(SchemaFailure::InvalidValue)?;
        let index = self
            .index_bytes
            .checked_add(delta.physical_index_bytes())
            .and_then(|bytes| bytes.checked_add(added_index))
            .ok_or(SchemaFailure::InvalidValue)?;
        let memory = self
            .memory_bytes
            .checked_add(delta.physical_memory_bytes())
            .and_then(|bytes| bytes.checked_add(added_memory))
            .ok_or(SchemaFailure::InvalidValue)?;
        if persistent > self.budget.max_persistent_bytes()
            || index > self.budget.max_index_bytes()
            || memory > self.budget.max_memory_bytes()
        {
            return Err(SchemaFailure::LimitExceeded);
        }
        if block_index.is_some() && self.block_indexes.len() >= MAX_BLOCK_INDEXES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let insertion = block_index.as_ref().map(|index| {
            self.block_indexes
                .binary_search_by_key(&index.identity, |known| known.identity)
        });
        if insertion.as_ref().is_some_and(|result| result.is_ok()) {
            return Err(SchemaFailure::InvalidValue);
        }
        // `Vec::insert` shifts every later element. Replay candidates are
        // immutable until publication, so a sequence of out-of-order blocks
        // can otherwise turn this path into quadratic work that is invisible
        // to the replay reservation. Preflight the complete shift charge
        // before mutating either vector so an observation failure remains
        // atomic.
        let block_shifts = insertion
            .as_ref()
            .and_then(|result| result.as_ref().err().copied())
            .map_or(0, |position| self.block_indexes.len() - position);
        let entry_shifts = delta.entries.iter().enumerate().try_fold(
            0_usize,
            |total, (new_entry_count, staged)| {
                let shifts = match self
                    .entries
                    .binary_search_by(|entry| entry.path.cmp(&staged.path))
                {
                    Ok(_) => 0,
                    Err(position) => self
                        .entries
                        .len()
                        .saturating_sub(position)
                        .saturating_add(new_entry_count),
                };
                total
                    .checked_add(shifts)
                    .ok_or(SchemaFailure::LimitExceeded)
            },
        )?;
        let mutation_work = 1_usize
            .checked_add(block_shifts)
            .and_then(|work| work.checked_add(entry_shifts))
            .ok_or(SchemaFailure::LimitExceeded)?;
        observer
            .observe_work(u64::try_from(mutation_work).map_err(|_| SchemaFailure::LimitExceeded)?)
            .map_err(SchemaFailure::Observed)?;
        if let Some(index) = block_index {
            let insertion = insertion
                .and_then(Result::err)
                .ok_or(SchemaFailure::InvalidValue)?;
            self.block_indexes
                .try_reserve_exact(1)
                .map_err(|_| SchemaFailure::AllocationUnavailable)?;
            self.block_indexes.insert(insertion, index);
        }
        self.persistent_bytes = persistent;
        self.index_bytes = index;
        self.memory_bytes = memory;
        for staged in delta.entries {
            self.apply_entry(staged)?;
        }
        self.overflow_records = self.overflow_records.saturating_add(delta.overflow_records);
        self.overflow_bytes = self.overflow_bytes.saturating_add(delta.overflow_bytes);
        Ok(())
    }

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
