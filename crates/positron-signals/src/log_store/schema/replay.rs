use super::catalog::SchemaCatalog;
use super::failure::SchemaFailure;
use super::index::TextIndexFraming;
use super::model::MAX_DISCOVERY_NODES;
use super::session::{SchemaReplayCandidate, SchemaSessionStore};
use crate::log_store::ScanObserver;

impl SchemaCatalog {
    pub(crate) fn try_clone(&self) -> Result<Self, SchemaFailure> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.capacity())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for entry in &self.entries {
            entries.push(entry.try_clone()?);
        }
        let mut block_indexes = Vec::new();
        block_indexes
            .try_reserve_exact(self.block_indexes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for block in &self.block_indexes {
            block_indexes.push(block.try_clone()?);
        }
        Ok(Self {
            tenant: self.tenant,
            budget: self.budget,
            entries,
            memory_bytes: self.memory_bytes,
            persistent_bytes: self.persistent_bytes,
            index_bytes: self.index_bytes,
            overflow_records: self.overflow_records,
            overflow_bytes: self.overflow_bytes,
            block_indexes,
        })
    }

    pub(crate) fn try_clone_observed(
        &self,
        observer: &dyn ScanObserver,
    ) -> Result<Self, SchemaFailure> {
        let mut operations = 0_usize;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.capacity())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for entry in &self.entries {
            if operations.is_multiple_of(64) {
                observer.observe_work(1).map_err(SchemaFailure::Observed)?;
            }
            operations = operations
                .checked_add(1)
                .ok_or(SchemaFailure::LimitExceeded)?;
            entries.push(entry.try_clone()?);
        }
        let mut block_indexes = Vec::new();
        block_indexes
            .try_reserve_exact(self.block_indexes.len())
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for block in &self.block_indexes {
            if operations.is_multiple_of(64) {
                observer.observe_work(1).map_err(SchemaFailure::Observed)?;
            }
            operations = operations
                .checked_add(1)
                .ok_or(SchemaFailure::LimitExceeded)?;
            block_indexes.push(block.try_clone()?);
        }
        Ok(Self {
            tenant: self.tenant,
            budget: self.budget,
            entries,
            memory_bytes: self.memory_bytes,
            persistent_bytes: self.persistent_bytes,
            index_bytes: self.index_bytes,
            overflow_records: self.overflow_records,
            overflow_bytes: self.overflow_bytes,
            block_indexes,
        })
    }

    #[doc(hidden)]
    pub fn replay_clone_work_units(&self) -> Result<u64, SchemaFailure> {
        let operations = self
            .entries
            .len()
            .checked_add(self.block_indexes.len())
            .ok_or(SchemaFailure::LimitExceeded)?;
        if operations == 0 {
            return Ok(0);
        }
        u64::try_from(operations.div_ceil(64)).map_err(|_| SchemaFailure::LimitExceeded)
    }

    #[doc(hidden)]
    pub fn replay_mutation_setup_work_units(&self) -> Result<u64, SchemaFailure> {
        let quanta = self.block_indexes.len().div_ceil(64);
        u64::try_from(quanta)
            .ok()
            .and_then(|value| value.checked_mul(2))
            .ok_or(SchemaFailure::LimitExceeded)
    }

    #[doc(hidden)]
    pub fn replay_reconciliation_work_units(&self, blocks: usize) -> Result<u64, SchemaFailure> {
        self.replay_reconciliation_work_units_with_staged_entries(blocks, MAX_DISCOVERY_NODES)
    }

    pub(crate) fn replay_reconciliation_work_units_with_staged_entries(
        &self,
        blocks: usize,
        staged_entries_per_block: usize,
    ) -> Result<u64, SchemaFailure> {
        if staged_entries_per_block > MAX_DISCOVERY_NODES {
            return Err(SchemaFailure::LimitExceeded);
        }
        let block_len = self
            .block_indexes
            .len()
            .checked_add(blocks)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let per_block = block_len
            .checked_mul(10)
            .and_then(|value| value.checked_add(1))
            .ok_or(SchemaFailure::LimitExceeded)?;
        // Replay applies entries through sorted Vec insertion. A new path may
        // shift every bounded catalog slot, and staged paths shift one another
        // across blocks. Reserve the complete checked bound before mutation.
        let triangular_blocks = blocks
            .checked_mul(blocks.checked_add(1).ok_or(SchemaFailure::LimitExceeded)?)
            .and_then(|value| value.checked_div(2))
            .ok_or(SchemaFailure::LimitExceeded)?;
        let existing_entry_shifts = self
            .entries
            .len()
            .checked_mul(blocks)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let staged_entry_shifts = staged_entries_per_block
            .checked_mul(triangular_blocks)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let entry_preflight = staged_entries_per_block
            .checked_mul(blocks)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let entry_work = existing_entry_shifts
            .checked_add(staged_entry_shifts)
            .and_then(|value| value.checked_add(entry_preflight))
            .ok_or(SchemaFailure::LimitExceeded)?;
        u64::try_from(per_block)
            .ok()
            .and_then(|value| value.checked_mul(u64::try_from(blocks).ok()?))
            .and_then(|value| value.checked_add(u64::try_from(entry_work).ok()?))
            .ok_or(SchemaFailure::LimitExceeded)
    }

    #[doc(hidden)]
    pub fn replay_retention_work_units(&self) -> Result<u64, SchemaFailure> {
        let operations = self
            .block_indexes
            .len()
            .checked_mul(10)
            .and_then(|value| value.checked_add(1))
            .ok_or(SchemaFailure::LimitExceeded)?;
        u64::try_from(operations).map_err(|_| SchemaFailure::LimitExceeded)
    }

    pub(crate) fn prepare_replay_mutation_observed(
        &mut self,
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaFailure> {
        let quanta = self.block_indexes.len().div_ceil(64);
        if quanta == 0 {
            return Ok(());
        }
        observer
            .observe_work(u64::try_from(quanta).map_err(|_| SchemaFailure::LimitExceeded)?)
            .map_err(SchemaFailure::Observed)?;
        let (text_version, scalar_upgrade, text_upgrade) = self.block_indexes.iter().fold(
            (false, 0_usize, 0_usize),
            |(text, scalar, text_old), block| {
                (
                    text || block.text_summary.is_some()
                        || block.text_framing == TextIndexFraming::V1,
                    scalar.saturating_add(usize::from(
                        block.scalar_framing == super::index::ScalarIndexFraming::LegacyV1,
                    )),
                    text_old.saturating_add(usize::from(
                        block.text_framing == TextIndexFraming::LegacyV2,
                    )),
                )
            },
        );
        let text_upgrade = if text_version { text_upgrade } else { 0 };
        let framing_upgrade = scalar_upgrade
            .checked_add(text_upgrade)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let persistent = self
            .persistent_bytes
            .checked_add(framing_upgrade)
            .ok_or(SchemaFailure::LimitExceeded)?;
        let index = self
            .index_bytes
            .checked_add(framing_upgrade)
            .ok_or(SchemaFailure::LimitExceeded)?;
        if persistent > self.budget.max_persistent_bytes() || index > self.budget.max_index_bytes()
        {
            return Err(SchemaFailure::LimitExceeded);
        }
        self.persistent_bytes = persistent;
        self.index_bytes = index;
        for (index, block) in self.block_indexes.iter_mut().enumerate() {
            if index.is_multiple_of(64) {
                observer.observe_work(1).map_err(SchemaFailure::Observed)?;
            }
            block.scalar_framing = block.scalar_framing.for_mutation();
            if text_version {
                block.text_framing = block.text_framing.for_mutation();
            }
        }
        Ok(())
    }

    pub(crate) fn reconcile_block_identity_observed(
        &mut self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
        observer: &dyn ScanObserver,
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
        // Reconciliation clones every surviving sidecar. Admit that copy
        // before allocating; replacement accounting charges its own complete
        // vector traversal below.
        let work = self.block_indexes.len();
        observer
            .observe_work(u64::try_from(work).map_err(|_| SchemaFailure::LimitExceeded)?)
            .map_err(SchemaFailure::Observed)?;
        let mut next = Vec::new();
        next.try_reserve_exact(self.block_indexes.len().saturating_sub(1))
            .map_err(|_| SchemaFailure::AllocationUnavailable)?;
        for (index, block) in self.block_indexes.iter().enumerate() {
            if index != position {
                next.push(block.try_clone()?);
            }
        }
        self.replace_block_indexes_observed(next, 0, 0, 0, 0, observer)
    }

    pub(crate) fn retain_reachable_indexes_observed(
        &mut self,
        reachable: &[(positron_kernel::StoreBlockIdentity, [u8; 32])],
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaFailure> {
        let work = self.block_indexes.len();
        observer
            .observe_work(u64::try_from(work).map_err(|_| SchemaFailure::LimitExceeded)?)
            .map_err(SchemaFailure::Observed)?;
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
        self.replace_block_indexes_observed(next, 0, 0, 0, 0, observer)
    }
}

impl SchemaSessionStore {
    pub fn retain_reachable_indexes_work_units(&self) -> Result<u64, SchemaFailure> {
        self.catalog().replay_retention_work_units()
    }

    pub fn retain_reachable_indexes_observed(
        &mut self,
        reachable: &[(positron_kernel::StoreBlockIdentity, [u8; 32])],
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaFailure> {
        self.catalog
            .retain_reachable_indexes_observed(reachable, observer)
    }

    pub fn reconcile_block_identity_observed(
        &mut self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaFailure> {
        self.catalog
            .reconcile_block_identity_observed(identity, digest, observer)
    }
}

impl SchemaReplayCandidate<'_> {
    pub fn reconcile_block_identity_observed(
        &mut self,
        identity: positron_kernel::StoreBlockIdentity,
        digest: [u8; 32],
        observer: &dyn ScanObserver,
    ) -> Result<(), SchemaFailure> {
        self.catalog
            .reconcile_block_identity_observed(identity, digest, observer)
    }
}

impl SchemaSessionStore {
    #[doc(hidden)]
    pub fn replay_delta_work_units(
        &self,
        delta: &super::SchemaDelta,
        identity: positron_kernel::StoreBlockIdentity,
    ) -> Result<u64, SchemaFailure> {
        self.catalog
            .replay_delta_work_units(delta, delta.has_block_index().then_some(identity))
    }

    #[doc(hidden)]
    pub fn replay_reconciliation_work_units_with_staged_entries(
        &self,
        blocks: usize,
        staged_entries_per_block: usize,
    ) -> Result<u64, SchemaFailure> {
        self.catalog
            .replay_reconciliation_work_units_with_staged_entries(blocks, staged_entries_per_block)
    }
}

impl<'reservation> SchemaReplayCandidate<'reservation> {
    #[doc(hidden)]
    pub fn replay_reservation(
        &mut self,
    ) -> &mut positron_kernel::ResourceReservation<'reservation> {
        &mut self.reservation
    }

    #[doc(hidden)]
    pub fn replay_delta_work_units(
        &self,
        delta: &super::SchemaDelta,
        identity: positron_kernel::StoreBlockIdentity,
    ) -> Result<u64, SchemaFailure> {
        self.catalog
            .replay_delta_work_units(delta, delta.has_block_index().then_some(identity))
    }

    #[doc(hidden)]
    pub fn replay_reconciliation_work_units_with_staged_entries(
        &self,
        blocks: usize,
        staged_entries_per_block: usize,
    ) -> Result<u64, SchemaFailure> {
        self.catalog
            .replay_reconciliation_work_units_with_staged_entries(blocks, staged_entries_per_block)
    }
}
