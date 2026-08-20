use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::index::{BLOCK_INDEX_HEADER_BYTES, INDEX_HEADER_BYTES, SCALAR_VALUES_MAGIC};
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
        self.remove_block_index(position)
    }

    pub(crate) fn retain_reachable_indexes(
        &mut self,
        reachable: &[(positron_kernel::StoreBlockIdentity, [u8; 32])],
    ) -> Result<(), SchemaFailure> {
        let mut position = self.block_indexes.len();
        while position > 0 {
            position -= 1;
            let keep = self.block_indexes.get(position).is_some_and(|index| {
                reachable
                    .binary_search(&(index.identity, index.digest))
                    .is_ok()
            });
            if !keep {
                self.remove_block_index(position)?;
            }
        }
        Ok(())
    }

    fn remove_block_index(&mut self, position: usize) -> Result<(), SchemaFailure> {
        let block = self
            .block_indexes
            .get(position)
            .ok_or(SchemaFailure::InvalidValue)?;
        let mut wire = BLOCK_INDEX_HEADER_BYTES;
        let mut memory = super::SchemaBudget::block_index_memory_bytes();
        for path in &block.paths {
            wire = wire
                .checked_add(path.encoded_bytes()?)
                .ok_or(SchemaFailure::LimitExceeded)?;
            memory = memory
                .checked_add(path.memory_bytes()?)
                .ok_or(SchemaFailure::LimitExceeded)?;
        }
        if block.paths.iter().any(|path| !path.values.is_empty()) {
            wire = wire
                .checked_add(SCALAR_VALUES_MAGIC.len())
                .ok_or(SchemaFailure::LimitExceeded)?;
        }
        if self.block_indexes.len() == 1 {
            wire = wire
                .checked_add(INDEX_HEADER_BYTES)
                .ok_or(SchemaFailure::LimitExceeded)?;
        }
        self.persistent_bytes = self
            .persistent_bytes
            .checked_sub(wire)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.index_bytes = self
            .index_bytes
            .checked_sub(wire)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.memory_bytes = self
            .memory_bytes
            .checked_sub(memory)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.block_indexes.remove(position);
        Ok(())
    }

    pub(crate) fn install_query_index(
        &mut self,
        index: super::index::SchemaBlockIndex,
    ) -> Result<(), SchemaFailure> {
        if !index.semantically_valid(&self.entries) {
            return Err(SchemaFailure::InvalidValue);
        }
        let path = index.paths.first().ok_or(SchemaFailure::InvalidValue)?;
        let path_wire = path.encoded_bytes()?;
        let path_memory = path.memory_bytes()?;
        match self
            .block_indexes
            .binary_search_by_key(&index.identity, |known| known.identity)
        {
            Ok(position) => self.merge_query_index(position, index, path_wire, path_memory),
            Err(position) => self.insert_query_index(position, index, path_wire, path_memory),
        }
    }

    fn merge_query_index(
        &mut self,
        position: usize,
        mut index: super::index::SchemaBlockIndex,
        wire: usize,
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
                for value in path.values {
                    if merged.values.contains(&value) {
                        continue;
                    }
                    merged
                        .values
                        .try_reserve_exact(1)
                        .map_err(|_| SchemaFailure::AllocationUnavailable)?;
                    merged.values.push(value);
                }
                merged.values.sort_unstable();
                if &merged == current {
                    return Ok(());
                }
                let old_wire = current.encoded_bytes()?;
                let new_wire = merged.encoded_bytes()?;
                let old_memory = current.memory_bytes()?;
                let new_memory = merged.memory_bytes()?;
                let old_has_values = known.paths.iter().any(|indexed| !indexed.values.is_empty());
                let new_has_values = known.paths.iter().enumerate().any(|(path_index, indexed)| {
                    !indexed.values.is_empty()
                        || path_index == existing && !merged.values.is_empty()
                });
                let marker = if !old_has_values && new_has_values {
                    SCALAR_VALUES_MAGIC.len()
                } else {
                    0
                };
                let added_wire = new_wire
                    .checked_sub(old_wire)
                    .map_or(marker, |value| value.saturating_add(marker));
                let added_memory = new_memory.checked_sub(old_memory).map_or(0, |value| value);
                self.ensure_index_cost(added_wire, added_memory)?;
                let known = self
                    .block_indexes
                    .get_mut(position)
                    .ok_or(SchemaFailure::InvalidValue)?;
                let existing = known
                    .paths
                    .get_mut(existing)
                    .ok_or(SchemaFailure::InvalidValue)?;
                *existing = merged;
                return self.add_index_cost(added_wire, added_memory);
            },
            Err(insertion) => insertion,
        };
        let marker = if !path.values.is_empty()
            && !known.paths.iter().any(|indexed| !indexed.values.is_empty())
        {
            SCALAR_VALUES_MAGIC.len()
        } else {
            0
        };
        self.ensure_index_cost(
            wire.checked_add(marker)
                .ok_or(SchemaFailure::LimitExceeded)?,
            memory,
        )?;
        let known = self
            .block_indexes
            .get_mut(position)
            .ok_or(SchemaFailure::InvalidValue)?;
        known
            .paths
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        known.paths.insert(insertion, path);
        self.add_index_cost(
            wire.checked_add(marker)
                .ok_or(SchemaFailure::LimitExceeded)?,
            memory,
        )
    }

    fn insert_query_index(
        &mut self,
        position: usize,
        index: super::index::SchemaBlockIndex,
        path_wire: usize,
        path_memory: usize,
    ) -> Result<(), SchemaFailure> {
        if self.block_indexes.len() >= super::index::MAX_BLOCK_INDEXES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let first = self.block_indexes.is_empty();
        let wire = path_wire
            .checked_add(BLOCK_INDEX_HEADER_BYTES)
            .and_then(|value| {
                value.checked_add(
                    if index
                        .paths
                        .first()
                        .is_some_and(|path| !path.values.is_empty())
                    {
                        SCALAR_VALUES_MAGIC.len()
                    } else {
                        0
                    },
                )
            })
            .and_then(|value| value.checked_add(if first { INDEX_HEADER_BYTES } else { 0 }))
            .ok_or(SchemaFailure::LimitExceeded)?;
        let memory = path_memory
            .checked_add(super::SchemaBudget::block_index_memory_bytes())
            .ok_or(SchemaFailure::LimitExceeded)?;
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
            .get_mut(position)
            .ok_or(SchemaFailure::InvalidPath)?;
        entry.query_uses = 0;
        if entry.observations >= 2 || !entry.promoted {
            return Ok(());
        }
        let entry_bytes = entry.index_bytes;
        entry.promoted = false;
        entry.index_bytes = 0;
        self.index_bytes = self
            .index_bytes
            .checked_sub(entry_bytes)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.remove_path_indexes(path)
    }

    fn remove_path_indexes(&mut self, path: &SchemaPath) -> Result<(), SchemaFailure> {
        let had_blocks = !self.block_indexes.is_empty();
        let mut removed_wire = 0_usize;
        let mut removed_memory = 0_usize;
        let mut emptied = 0_usize;
        let mut removed_scalar_markers = 0_usize;
        for block in &mut self.block_indexes {
            if let Ok(position) = block
                .paths
                .binary_search_by(|known| known.wire_cmp_path(path))
            {
                let indexed = block
                    .paths
                    .get(position)
                    .ok_or(SchemaFailure::InvalidValue)?;
                let block_had_scalar_values =
                    block.paths.iter().any(|known| !known.values.is_empty());
                removed_wire = removed_wire
                    .checked_add(indexed.encoded_bytes()?)
                    .ok_or(SchemaFailure::LimitExceeded)?;
                removed_memory = removed_memory
                    .checked_add(indexed.memory_bytes()?)
                    .ok_or(SchemaFailure::LimitExceeded)?;
                if block.paths.len() == 1 && block_had_scalar_values {
                    removed_scalar_markers = removed_scalar_markers.saturating_add(1);
                }
                block.paths.remove(position);
                emptied += usize::from(block.paths.is_empty());
            }
        }
        self.block_indexes.retain(|block| !block.paths.is_empty());
        removed_wire = removed_wire
            .checked_add(
                emptied
                    .checked_mul(BLOCK_INDEX_HEADER_BYTES)
                    .ok_or(SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)?;
        removed_wire = removed_wire
            .checked_add(
                removed_scalar_markers
                    .checked_mul(SCALAR_VALUES_MAGIC.len())
                    .ok_or(SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)?;
        removed_memory = removed_memory
            .checked_add(
                emptied
                    .checked_mul(super::SchemaBudget::block_index_memory_bytes())
                    .ok_or(SchemaFailure::LimitExceeded)?,
            )
            .ok_or(SchemaFailure::LimitExceeded)?;
        if had_blocks && self.block_indexes.is_empty() {
            removed_wire = removed_wire
                .checked_add(INDEX_HEADER_BYTES)
                .ok_or(SchemaFailure::LimitExceeded)?;
        }
        self.persistent_bytes = self
            .persistent_bytes
            .checked_sub(removed_wire)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.index_bytes = self
            .index_bytes
            .checked_sub(removed_wire)
            .ok_or(SchemaFailure::InvalidValue)?;
        self.memory_bytes = self
            .memory_bytes
            .checked_sub(removed_memory)
            .ok_or(SchemaFailure::InvalidValue)?;
        Ok(())
    }
}
