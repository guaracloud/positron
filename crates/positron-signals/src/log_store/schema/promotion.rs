use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::index::{INDEX_HEADER_BYTES, MAX_INDEX_VALUES};
use super::model::{SchemaPath, promoted_index_bytes};

impl SchemaCatalog {
    pub(crate) fn reconcile_block_identity(
        &mut self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
    ) -> Result<(), SchemaFailure> {
        let Ok(position) = self
            .block_indexes
            .binary_search_by_key(&identity, |known| known.identity)
        else {
            return Ok(());
        };
        if self
            .block_indexes
            .get(position)
            .is_some_and(|known| known.digest == digest)
        {
            return Ok(());
        }
        let mut next = Vec::new();
        next.try_reserve_exact(self.block_indexes.len().saturating_sub(1))
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for (index, block) in self.block_indexes.iter().enumerate() {
            if index != position {
                next.push(block.try_clone()?);
            }
        }
        self.replace_block_indexes(next, 0)
    }

    pub(crate) fn retain_reachable_indexes(
        &mut self,
        reachable: &[(positron_kernel::StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaFailure> {
        let mut next = Vec::new();
        next.try_reserve_exact(self.block_indexes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for index in &self.block_indexes {
            let keep = reachable
                .binary_search(&(index.identity, index.digest))
                .is_ok();
            if keep {
                next.push(index.try_clone()?);
            }
        }
        self.replace_block_indexes(next, 0)
    }

    pub(crate) fn install_query_index(
        &mut self,
        index: super::index::SchemaBlockIndex,
    ) -> Result<(), SchemaFailure> {
        if !index.semantically_valid(&self.entries) {
            return Err(SchemaFailure::InvalidValue);
        }
        let path = index.paths.first().ok_or(SchemaFailure::InvalidValue)?;
        let path_memory = path.memory_bytes()?;
        if let Ok(position) = self
            .block_indexes
            .binary_search_by_key(&index.identity, |known| known.identity)
            && self
                .block_indexes
                .get(position)
                .is_some_and(|known| known.digest != index.digest)
        {
            return Err(SchemaFailure::InvalidValue);
        }
        self.upgrade_legacy_survivors()?;
        match self
            .block_indexes
            .binary_search_by_key(&index.identity, |known| known.identity)
        {
            Ok(position) => self.merge_query_index(position, index, path_memory),
            Err(position) => self.insert_query_index(position, index),
        }
    }

    fn merge_query_index(
        &mut self,
        position: usize,
        mut index: super::index::SchemaBlockIndex,
        memory: usize,
    ) -> Result<(), SchemaFailure> {
        let known = self
            .block_indexes
            .get(position)
            .ok_or(SchemaFailure::InvalidValue)?;
        if known.digest != index.digest {
            return Err(SchemaFailure::InvalidValue);
        }
        let path = index.paths.pop().ok_or(SchemaFailure::InvalidValue)?;
        let insertion = match known
            .paths
            .binary_search_by(|item| item.wire_cmp_path(&path.path))
        {
            Ok(existing) => {
                let current = known
                    .paths
                    .get(existing)
                    .ok_or(SchemaFailure::InvalidValue)?;
                let mut merged = current.try_clone()?;
                merged.kind_mask |= path.kind_mask;
                let mut values_overflowed = false;
                for value in path.values {
                    if merged.values.contains(&value) {
                        continue;
                    }
                    if merged.values.len() == MAX_INDEX_VALUES {
                        values_overflowed = true;
                        break;
                    }
                    merged
                        .values
                        .try_reserve_exact(1)
                        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                    merged.values.push(value);
                }
                if values_overflowed {
                    merged.values.clear();
                }
                merged.values.sort_unstable();
                if &merged == current {
                    return Ok(());
                }
                let old_wire = known.paths_encoded_bytes_for(&known.paths)?;
                let mut projected = Vec::new();
                projected
                    .try_reserve_exact(known.paths.len())
                    .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                for (path_index, known_path) in known.paths.iter().enumerate() {
                    if path_index == existing {
                        projected.push(merged.try_clone()?);
                    } else {
                        projected.push(known_path.try_clone()?);
                    }
                }
                let new_wire = known.paths_encoded_bytes_after_mutation(&projected)?;
                let old_memory = current.memory_bytes()?;
                let new_memory = merged.memory_bytes()?;
                let next_index_bytes = self
                    .index_bytes
                    .checked_sub(old_wire)
                    .and_then(|bytes| bytes.checked_add(new_wire))
                    .ok_or(SchemaFailure::InvalidValue)?;
                let next_persistent_bytes = self
                    .persistent_bytes
                    .checked_sub(old_wire)
                    .and_then(|bytes| bytes.checked_add(new_wire))
                    .ok_or(SchemaFailure::InvalidValue)?;
                let next_memory_bytes = self
                    .memory_bytes
                    .checked_sub(old_memory)
                    .and_then(|bytes| bytes.checked_add(new_memory))
                    .ok_or(SchemaFailure::InvalidValue)?;
                if next_index_bytes > self.budget.max_index_bytes()
                    || next_persistent_bytes > self.budget.max_persistent_bytes()
                    || next_memory_bytes > self.budget.max_memory_bytes()
                {
                    return Err(SchemaFailure::LimitExceeded);
                }
                let known = self
                    .block_indexes
                    .get_mut(position)
                    .ok_or(SchemaFailure::InvalidValue)?;
                let existing = known
                    .paths
                    .get_mut(existing)
                    .ok_or(SchemaFailure::InvalidValue)?;
                *existing = merged;
                known.scalar_framing = known.scalar_framing.for_mutation();
                self.index_bytes = next_index_bytes;
                self.persistent_bytes = next_persistent_bytes;
                self.memory_bytes = next_memory_bytes;
                return Ok(());
            },
            Err(insertion) => insertion,
        };
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(known.paths.len().saturating_add(1))
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for known_path in &known.paths {
            projected.push(known_path.try_clone()?);
        }
        projected.insert(insertion, path.try_clone()?);
        let old_wire = known.paths_encoded_bytes_for(&known.paths)?;
        let new_wire = known.paths_encoded_bytes_after_mutation(&projected)?;
        let added_wire = new_wire
            .checked_sub(old_wire)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.ensure_index_cost(added_wire, memory)?;
        let known = self
            .block_indexes
            .get_mut(position)
            .ok_or(SchemaFailure::InvalidValue)?;
        known
            .paths
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        known.paths.insert(insertion, path);
        known.scalar_framing = known.scalar_framing.for_mutation();
        self.add_index_cost(added_wire, memory)
    }

    fn insert_query_index(
        &mut self,
        position: usize,
        index: super::index::SchemaBlockIndex,
    ) -> Result<(), SchemaFailure> {
        if self.block_indexes.len() >= super::index::MAX_BLOCK_INDEXES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let first = self.block_indexes.is_empty();
        let wire = index
            .encoded_bytes()?
            .checked_add(if first { INDEX_HEADER_BYTES } else { 0 })
            .ok_or(SchemaFailure::LimitExceeded)?;
        let memory = index.paths.iter().try_fold(
            super::SchemaBudget::block_index_memory_bytes(),
            |total, path| {
                total
                    .checked_add(path.memory_bytes()?)
                    .ok_or(SchemaFailure::LimitExceeded)
            },
        )?;
        self.ensure_index_cost(wire, memory)?;
        self.block_indexes
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        self.block_indexes.insert(position, index);
        self.add_index_cost(wire, memory)
    }

    fn ensure_index_cost(&self, wire: usize, memory: usize) -> Result<(), SchemaFailure> {
        let fits = self
            .index_bytes
            .checked_add(wire)
            .is_some_and(|value| value <= self.budget.max_index_bytes())
            && self
                .persistent_bytes
                .checked_add(wire)
                .is_some_and(|value| value <= self.budget.max_persistent_bytes())
            && self
                .memory_bytes
                .checked_add(memory)
                .is_some_and(|value| value <= self.budget.max_memory_bytes());
        if fits {
            Ok(())
        } else {
            Err(SchemaFailure::LimitExceeded)
        }
    }

    fn upgrade_legacy_survivors(&mut self) -> Result<(), SchemaFailure> {
        if self
            .block_indexes
            .iter()
            .all(|block| block.scalar_framing.for_mutation() == block.scalar_framing)
        {
            return Ok(());
        }
        let mut next = Vec::new();
        next.try_reserve_exact(self.block_indexes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for block in &self.block_indexes {
            next.push(block.try_clone()?);
        }
        self.replace_block_indexes(next, 0)
    }

    fn replace_block_indexes(
        &mut self,
        mut next: Vec<super::index::SchemaBlockIndex>,
        entry_index_reduction: usize,
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
            .ok_or(SchemaFailure::InvalidValue)?;
        let next_index = self
            .index_bytes
            .checked_sub(old_wire)
            .and_then(|bytes| bytes.checked_add(new_wire))
            .and_then(|bytes| bytes.checked_sub(entry_index_reduction))
            .ok_or(SchemaFailure::InvalidValue)?;
        let next_memory = self
            .memory_bytes
            .checked_sub(old_memory)
            .and_then(|bytes| bytes.checked_add(new_memory))
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

    fn block_indexes_wire(
        blocks: &[super::index::SchemaBlockIndex],
    ) -> Result<usize, SchemaFailure> {
        if blocks.is_empty() {
            return Ok(0);
        }
        blocks.iter().try_fold(INDEX_HEADER_BYTES, |total, block| {
            total
                .checked_add(block.encoded_bytes()?)
                .ok_or(SchemaFailure::LimitExceeded)
        })
    }

    fn block_indexes_memory(
        blocks: &[super::index::SchemaBlockIndex],
    ) -> Result<usize, SchemaFailure> {
        blocks.iter().try_fold(0_usize, |total, block| {
            let paths = block.paths.iter().try_fold(
                super::SchemaBudget::block_index_memory_bytes(),
                |memory, path| {
                    memory
                        .checked_add(path.memory_bytes()?)
                        .ok_or(SchemaFailure::LimitExceeded)
                },
            )?;
            total.checked_add(paths).ok_or(SchemaFailure::LimitExceeded)
        })
    }

    fn add_index_cost(&mut self, wire: usize, memory: usize) -> Result<(), SchemaFailure> {
        self.index_bytes = self
            .index_bytes
            .checked_add(wire)
            .ok_or(SchemaFailure::LimitExceeded)?;
        self.persistent_bytes = self
            .persistent_bytes
            .checked_add(wire)
            .ok_or(SchemaFailure::LimitExceeded)?;
        self.memory_bytes = self
            .memory_bytes
            .checked_add(memory)
            .ok_or(SchemaFailure::LimitExceeded)?;
        Ok(())
    }

    pub(crate) fn record_query_use(&mut self, path: &SchemaPath) -> Result<(), SchemaFailure> {
        let position = self
            .entry_index(path)
            .map_err(|_| SchemaFailure::InvalidPath)?;
        let entry = self
            .entries
            .get(position)
            .ok_or(SchemaFailure::InvalidPath)?;
        let next_uses = entry.query_uses.saturating_add(1);
        if entry.promoted {
            self.entries
                .get_mut(position)
                .ok_or(SchemaFailure::InvalidPath)?
                .query_uses = next_uses;
            return Ok(());
        }
        let bytes = promoted_index_bytes(&entry.variants);
        let next_index = self
            .index_bytes
            .checked_add(bytes)
            .filter(|used| *used <= self.budget.max_index_bytes())
            .ok_or(SchemaFailure::LimitExceeded)?;
        let entry = self
            .entries
            .get_mut(position)
            .ok_or(SchemaFailure::InvalidPath)?;
        entry.query_uses = next_uses;
        entry.promoted = bytes > 0;
        entry.index_bytes = bytes;
        self.index_bytes = next_index;
        Ok(())
    }

    pub(crate) fn remove_query_evidence(&mut self, path: &SchemaPath) -> Result<(), SchemaFailure> {
        let position = self
            .entry_index(path)
            .map_err(|_| SchemaFailure::InvalidPath)?;
        let entry = self
            .entries
            .get(position)
            .ok_or(SchemaFailure::InvalidPath)?;
        if entry.observations >= 2 || !entry.promoted {
            self.entries
                .get_mut(position)
                .ok_or(SchemaFailure::InvalidPath)?
                .query_uses = 0;
            return Ok(());
        }
        let entry_bytes = entry.index_bytes;
        self.remove_path_indexes(path, entry_bytes)?;
        let entry = self
            .entries
            .get_mut(position)
            .ok_or(SchemaFailure::InvalidPath)?;
        entry.query_uses = 0;
        entry.promoted = false;
        entry.index_bytes = 0;
        Ok(())
    }

    fn remove_path_indexes(
        &mut self,
        path: &SchemaPath,
        entry_index_reduction: usize,
    ) -> Result<(), SchemaFailure> {
        let mut next = Vec::new();
        next.try_reserve_exact(self.block_indexes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for block in &self.block_indexes {
            let mut candidate = block.try_clone()?;
            if let Ok(position) = block
                .paths
                .binary_search_by(|known| known.wire_cmp_path(path))
            {
                candidate.paths.remove(position);
            }
            if !candidate.paths.is_empty() {
                next.push(candidate);
            }
        }
        self.replace_block_indexes(next, entry_index_reduction)
    }
}
