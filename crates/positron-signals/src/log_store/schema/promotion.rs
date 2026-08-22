use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::index::MAX_INDEX_VALUES;
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
        self.replace_block_indexes(next, 0, 0, 0, 0)
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
        self.replace_block_indexes(next, 0, 0, 0, 0)
    }

    pub(crate) fn install_query_index(
        &mut self,
        index: super::index::SchemaBlockIndex,
    ) -> Result<(), SchemaFailure> {
        if !index.semantically_valid(&self.entries) {
            return Err(SchemaFailure::InvalidValue);
        }
        let path = index.paths.first().ok_or(SchemaFailure::InvalidValue)?;
        path.memory_bytes()?;
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
        match self
            .block_indexes
            .binary_search_by_key(&index.identity, |known| known.identity)
        {
            Ok(position) => self.merge_query_index(position, index),
            Err(position) => self.insert_query_index(position, index),
        }
    }

    fn merge_query_index(
        &mut self,
        position: usize,
        mut index: super::index::SchemaBlockIndex,
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
                let mut next = self.clone_block_indexes()?;
                next.get_mut(position)
                    .ok_or(SchemaFailure::InvalidValue)?
                    .paths = projected;
                return self.replace_block_indexes(next, 0, 0, 0, 0);
            },
            Err(insertion) => insertion,
        };
        let mut next = self.clone_block_indexes()?;
        let known = next.get_mut(position).ok_or(SchemaFailure::InvalidValue)?;
        known
            .paths
            .try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        known.paths.insert(insertion, path);
        self.replace_block_indexes(next, 0, 0, 0, 0)
    }

    fn insert_query_index(
        &mut self,
        position: usize,
        index: super::index::SchemaBlockIndex,
    ) -> Result<(), SchemaFailure> {
        if self.block_indexes.len() >= super::index::MAX_BLOCK_INDEXES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let mut next = self.clone_block_indexes()?;
        next.try_reserve_exact(1)
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        next.insert(position, index);
        self.replace_block_indexes(next, 0, 0, 0, 0)
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
            if !candidate.paths.is_empty() || candidate.text_summary.is_some() {
                next.push(candidate);
            }
        }
        self.replace_block_indexes(next, entry_index_reduction, 0, 0, 0)
    }
}
