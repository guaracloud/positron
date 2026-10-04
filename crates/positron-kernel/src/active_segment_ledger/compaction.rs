use std::num::NonZeroU64;

use sha2::{Digest, Sha256};

use crate::RecoveryWorkKind;
use crate::data_protection::{DataProtection, FrameLimits, FrameSequence, SegmentFramePurpose};

use super::capacity::retained_claim;
use super::format::{SegmentMetadata, SegmentState};
use super::publication::{
    fresh_metadata, publish_exact_scope_segments_with_task_replacement, publish_segments,
};
use super::reconstruction::reconstruct;
use super::recovery::RecoveryMode;
use super::storage::{AppendFailure, LedgerStorage, NextFrontier};
use super::{
    ActiveSegmentLedger, CommittedBlock, CompactionBlock, CompactionPreparation,
    CompactionPublication, LedgerFailure, LedgerFailureCode, RecoveryWorkClaim, SegmentRetention,
};

const MAX_COMPACTION_BLOCKS: usize = 1_024;
const MAX_ENCODED_FRAME_BYTES: u32 = super::MAX_ENCODED_FRAME_BYTES;

/// A caller-chosen, kernel-verified fixed-bucket compaction descriptor. The
/// durable binding is submitted before dispatch; the payload is not copied or
/// written during this admission step.
pub struct PreparedCompactionTask {
    task: crate::MaintenanceTask,
    binding: crate::CompactionBinding,
}

impl PreparedCompactionTask {
    #[must_use]
    pub const fn task(&self) -> &crate::MaintenanceTask {
        &self.task
    }

    pub fn submit_and_persist(
        self,
        coordinator: &crate::MaintenanceCoordinator,
        catalog: &crate::Catalog<'_>,
        submitted_at: u64,
    ) -> Result<crate::MaintenanceTask, LedgerFailure> {
        coordinator
            .submit_compaction_and_persist(catalog, self.task.clone(), self.binding, submitted_at)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))
    }
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Selects one authenticated ingest-time bucket from an existing sealed
    /// source. Callers cannot supply a raw timestamp or retention bounds.
    pub fn sealed_compaction_bucket(&self) -> Result<super::RetentionBucket, LedgerFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        state.require_healthy()?;
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let policy = basis.retention_policy(self.scope.signal_kind())?;
        if policy.instance() != self.catalog.instance() || policy.tenant() != self.scope.tenant_id()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        let metadata = self.storage.catalog_segments(&basis, self.scope)?;
        let block = metadata
            .iter()
            .filter(|segment| segment.state == SegmentState::Sealed)
            .find_map(|segment| {
                state
                    .blocks
                    .iter()
                    .find(|block| block.segment == segment.id)
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::InvalidInput))?;
        let SegmentRetention::Complete(ingest_time) = block.block_retention else {
            return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
        };
        super::RetentionBucket::for_ingest_time(
            self.scope.tenant_id(),
            self.scope.signal_kind(),
            ingest_time,
            policy.retention_seconds(),
        )
    }

    /// Creates the only durable descriptor for the complete currently-sealed
    /// source manifest and one caller-requested fixed retention bucket.
    ///
    /// This deliberately reads only Catalog metadata and sealed file bounds.
    /// The signal adapter selects and decodes actual bucket blocks only after
    /// the coordinator has persisted and admitted this descriptor.
    pub fn prepare_compaction_task(
        &self,
        bucket: super::RetentionBucket,
        identity: crate::MaintenanceTaskId,
    ) -> Result<PreparedCompactionTask, LedgerFailure> {
        if bucket.tenant() != self.scope.tenant_id()
            || bucket.signal_kind() != self.scope.signal_kind()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let policy = basis.retention_policy(self.scope.signal_kind())?;
        if policy.instance() != self.catalog.instance() || policy.tenant() != self.scope.tenant_id()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        let metadata = self.storage.catalog_segments(&basis, self.scope)?;
        let (inputs, source_bytes, source_blocks) = compaction_source_manifest_and_bounds(
            &self.storage,
            &metadata,
            &self.protection,
            self.catalog.instance(),
        )?;
        let scope = crate::MaintenanceScope::segment(
            self.scope.tenant_id(),
            self.scope.signal_kind(),
            self.scope.shard_id(),
        );
        let binding = crate::CompactionBinding::new(
            scope,
            policy,
            bucket,
            maintenance_source_manifest_digest(self.scope, &inputs)?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        let task_record_bytes =
            crate::maintenance::compaction_task_record_bytes(inputs.len(), binding)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let task_record_working_bytes =
            crate::maintenance::compaction_task_record_working_bytes(inputs.len(), binding)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let catalog_bytes = basis
            .plaintext_objects()
            .try_fold(0_usize, |total, bytes| {
                total
                    .checked_add(bytes.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
            })?
            .checked_add(task_record_bytes)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservations = super::capacity::compaction_claim(
            source_bytes,
            source_blocks,
            catalog_bytes,
            basis
                .plaintext_object_count()
                .checked_add(1)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            task_record_working_bytes,
        )?;
        let task = crate::MaintenanceTask::with_contract(
            identity,
            crate::MaintenanceTaskClass::Compaction,
            scope,
            crate::MaintenanceTrigger::Event,
            crate::MaintenancePreconditions::new(basis.number(), 1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            inputs,
            Vec::new(),
            reservations,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        Ok(PreparedCompactionTask { task, binding })
    }

    /// Checks the payload-bearing execution preparation against the exact
    /// ordinary grant owned by the dispatched coordinator task. It never
    /// reserves recovery capacity.
    pub fn prepare_compaction_for_maintenance(
        &self,
        execution: &crate::MaintenanceExecution<'_>,
    ) -> Result<(), LedgerFailure> {
        if execution.task().class() != crate::MaintenanceTaskClass::Compaction
            || !execution
                .reservation()
                .authorizes_ordinary_compaction(self.authority.governor(), self.scope.tenant_id())
        {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let binding = crate::CompactionBinding::from_checkpoint(execution.task_checkpoint())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let policy = basis.retention_policy(self.scope.signal_kind())?;
        let metadata = self.storage.catalog_segments(&basis, self.scope)?;
        let (inputs, source_bytes, source_blocks) = compaction_source_manifest_and_bounds(
            &self.storage,
            &metadata,
            &self.protection,
            self.catalog.instance(),
        )?;
        if binding.scope()
            != crate::MaintenanceScope::segment(
                self.scope.tenant_id(),
                self.scope.signal_kind(),
                self.scope.shard_id(),
            )
            || !binding.matches_policy(policy)
            || execution.task().inputs() != inputs
            || binding.source_digest() != maintenance_source_manifest_digest(self.scope, &inputs)?
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let task_record_working_bytes =
            crate::maintenance::compaction_task_record_working_bytes(inputs.len(), binding)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let catalog_bytes = basis
            .plaintext_objects()
            .try_fold(0_usize, |total, bytes| {
                total
                    .checked_add(bytes.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
            })?;
        let current = super::capacity::compaction_claim(
            source_bytes,
            source_blocks,
            catalog_bytes,
            basis.plaintext_object_count(),
            task_record_working_bytes,
        )?;
        if crate::ResourceDimension::ALL.iter().any(|dimension| {
            current.get(*dimension) > execution.reservation().granted().get(*dimension)
        }) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        Ok(())
    }

    /// Rechecks a pre-admitted running task after the adapter has read its
    /// bounded payloads. Call `prepare_compaction_for_maintenance` before
    /// that read; this second fence rejects catalog or source races.
    pub fn prepare_compaction_payload_for_maintenance(
        &self,
        snapshot: &super::LedgerSnapshot<'_>,
        execution: &crate::MaintenanceExecution<'_>,
    ) -> Result<CompactionPreparation<'kernel>, LedgerFailure> {
        self.prepare_compaction_for_maintenance(execution)?;
        let binding = crate::CompactionBinding::from_checkpoint(execution.task_checkpoint())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        let policy = self
            .catalog
            .pin()?
            .retention_policy(self.scope.signal_kind())?;
        self.prepare_compaction_from_grant(
            snapshot,
            policy,
            binding,
            execution.task().inputs().len(),
            execution.reservation().granted(),
        )
    }
    /// Admits the bounded copy-on-write peak while the caller still owns only
    /// an immutable snapshot. No input payload allocation is needed to make
    /// this decision.
    pub fn prepare_compaction(
        &self,
        snapshot: &super::LedgerSnapshot<'_>,
    ) -> Result<CompactionPreparation<'kernel>, LedgerFailure> {
        self.prepare_compaction_inner(snapshot, None, 0, 0)
    }

    /// Admits compaction against one authenticated POSGOV03 retention policy.
    /// Later Catalog generations remain eligible only when that exact policy
    /// object and duration are unchanged.
    pub fn prepare_compaction_with_policy(
        &self,
        snapshot: &super::LedgerSnapshot<'_>,
        policy: crate::CatalogLogRetentionPolicy,
    ) -> Result<CompactionPreparation<'kernel>, LedgerFailure> {
        self.prepare_compaction_inner(snapshot, Some(policy), 0, 0)
    }

    fn prepare_compaction_inner(
        &self,
        snapshot: &super::LedgerSnapshot<'_>,
        expected_policy: Option<crate::CatalogLogRetentionPolicy>,
        anticipated_catalog_bytes: usize,
        terminal_record_working_bytes: usize,
    ) -> Result<CompactionPreparation<'kernel>, LedgerFailure> {
        if snapshot.scope() != self.scope {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        let payload_bytes = snapshot.blocks().iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.payload().len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
        })?;
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let basis_is_stale = match expected_policy {
            Some(expected) => basis.retention_policy(expected.signal_kind())? != expected,
            None => {
                basis.identity() != snapshot.catalog_identity()
                    || basis.number() != snapshot.catalog_generation()
            },
        };
        if basis_is_stale {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let catalog_bytes = basis
            .plaintext_objects()
            .try_fold(0_usize, |total, bytes| {
                total
                    .checked_add(bytes.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
            })?
            .checked_add(anticipated_catalog_bytes)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let maximum_blocks = snapshot.blocks().len();
        let claim = RecoveryWorkClaim::tenant(
            self.scope.tenant_id(),
            RecoveryWorkKind::EmergencyCompaction,
            super::capacity::compaction_claim(
                payload_bytes,
                maximum_blocks,
                catalog_bytes,
                basis
                    .plaintext_object_count()
                    .checked_add(usize::from(anticipated_catalog_bytes != 0))
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                terminal_record_working_bytes,
            )
            .map_err(|failure| LedgerFailure::new(failure.code()))?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let capacity = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        Ok(CompactionPreparation {
            granted: capacity.granted(),
            capacity: Some(capacity),
            coordinator_admitted: false,
            scope: snapshot.scope(),
            catalog_instance: self.catalog.instance(),
            catalog_identity: basis.identity(),
            catalog_generation: basis.number(),
            retention_policy: expected_policy,
            frontier: snapshot.frontier(),
            source_digest: snapshot_source_digest(snapshot)?,
            maximum_blocks,
            maximum_payload_bytes: payload_bytes,
        })
    }

    fn prepare_compaction_from_grant(
        &self,
        snapshot: &super::LedgerSnapshot<'_>,
        policy: crate::CatalogLogRetentionPolicy,
        binding: crate::CompactionBinding,
        input_count: usize,
        granted: crate::ResourceAmounts,
    ) -> Result<CompactionPreparation<'kernel>, LedgerFailure> {
        if snapshot.scope() != self.scope {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        let payload_bytes = snapshot.blocks().iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.payload().len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
        })?;
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        if basis.retention_policy(policy.signal_kind())? != policy {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let catalog_bytes = basis
            .plaintext_objects()
            .try_fold(0_usize, |total, bytes| {
                total
                    .checked_add(bytes.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
            })?;
        let terminal_record_working_bytes =
            crate::maintenance::compaction_task_record_working_bytes(input_count, binding)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let current_minimum = super::capacity::compaction_claim(
            payload_bytes,
            snapshot.blocks().len(),
            catalog_bytes,
            basis.plaintext_object_count(),
            terminal_record_working_bytes,
        )?;
        if crate::ResourceDimension::ALL
            .iter()
            .any(|dimension| current_minimum.get(*dimension) > granted.get(*dimension))
        {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        Ok(CompactionPreparation {
            capacity: None,
            granted,
            coordinator_admitted: true,
            scope: snapshot.scope(),
            catalog_instance: self.catalog.instance(),
            catalog_identity: basis.identity(),
            catalog_generation: basis.number(),
            retention_policy: Some(policy),
            frontier: snapshot.frontier(),
            source_digest: snapshot_source_digest(snapshot)?,
            maximum_blocks: snapshot.blocks().len(),
            maximum_payload_bytes: payload_bytes,
        })
    }

    /// Atomically replaces the supplied sealed blocks with copy-on-write
    /// sealed segments. The Log Store supplies already-verified canonical
    /// blocks; this kernel operation owns output encryption and publication.
    pub fn compact_sealed(
        &self,
        blocks: Vec<CompactionBlock>,
    ) -> Result<CompactionPublication, LedgerFailure> {
        if blocks.is_empty() || blocks.len() > MAX_COMPACTION_BLOCKS {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let snapshot = self.snapshot()?;
        let preparation = self.prepare_compaction(&snapshot)?;
        self.compact_sealed_with_cancellation(blocks, preparation, || false)
    }

    /// Commits a pre-admitted compaction while checking cancellation at every
    /// kernel-owned durability checkpoint. A check after output mutation is
    /// reported as recovery-required or ambiguous, never as pre-mutation.
    pub fn compact_sealed_with_cancellation<F>(
        &self,
        blocks: Vec<CompactionBlock>,
        preparation: CompactionPreparation<'kernel>,
        is_cancelled: F,
    ) -> Result<CompactionPublication, LedgerFailure>
    where
        F: Fn() -> bool,
    {
        self.compact_sealed_with_cancellation_inner(blocks, preparation, is_cancelled, None)
    }

    /// Executes one already-admitted Compaction task and atomically publishes
    /// its terminal PMTC record with the replacement manifest.
    pub fn compact_sealed_with_maintenance<F>(
        &self,
        mut blocks: Vec<CompactionBlock>,
        preparation: CompactionPreparation<'kernel>,
        coordinator: &crate::MaintenanceCoordinator,
        execution: &crate::MaintenanceExecution<'_>,
        is_cancelled: F,
    ) -> Result<CompactionPublication, LedgerFailure>
    where
        F: Fn() -> bool,
    {
        if execution.task().class() != crate::MaintenanceTaskClass::Compaction
            || execution.task().scope()
                != crate::MaintenanceScope::segment(
                    self.scope.tenant_id(),
                    self.scope.signal_kind(),
                    self.scope.shard_id(),
                )
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        if !preparation.coordinator_admitted
            || !execution
                .reservation()
                .authorizes_ordinary_compaction(self.authority.governor(), self.scope.tenant_id())
        {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        blocks.sort_unstable_by_key(|block| block.position);
        let binding = crate::CompactionBinding::from_checkpoint(execution.task_checkpoint())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        if binding.scope()
            != crate::MaintenanceScope::segment(
                self.scope.tenant_id(),
                self.scope.signal_kind(),
                self.scope.shard_id(),
            )
            || blocks
                .iter()
                .any(|block| !binding.contains(block.ingest_time))
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let policy = basis.retention_policy(self.scope.signal_kind())?;
        if policy.instance() != self.catalog.instance()
            || !binding.matches_policy(policy)
            || preparation.retention_policy != Some(policy)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let terminal_record_working_bytes =
            crate::maintenance::compaction_task_record_working_bytes(
                execution.task().inputs().len(),
                binding,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        let current_payload_bytes = blocks.iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.payload.len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
        })?;
        let current_catalog_bytes =
            basis
                .plaintext_objects()
                .try_fold(0_usize, |total, bytes| {
                    total
                        .checked_add(bytes.len())
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
                })?;
        let current_minimum = super::capacity::compaction_claim(
            current_payload_bytes,
            blocks.len(),
            current_catalog_bytes,
            basis.plaintext_object_count(),
            terminal_record_working_bytes,
        )?;
        if crate::ResourceDimension::ALL.iter().any(|dimension| {
            current_minimum.get(*dimension) > preparation.granted.get(*dimension)
                || preparation.granted.get(*dimension)
                    != execution.reservation().granted().get(*dimension)
        }) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let metadata = self.storage.catalog_segments(&basis, self.scope)?;
        let (manifest, _, _) = compaction_source_manifest_and_bounds(
            &self.storage,
            &metadata,
            &self.protection,
            self.catalog.instance(),
        )?;
        if execution.task().inputs() != manifest
            || binding.source_digest() != maintenance_source_manifest_digest(self.scope, &manifest)?
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        if blocks.is_empty() {
            if is_cancelled() {
                return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
            }
            let state = self
                .state
                .lock()
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
            state.require_healthy()?;
            if state.frontier != preparation.frontier
                || snapshot_source_digest_from_blocks(self.scope, state.frontier, &state.blocks)?
                    != preparation.source_digest
                || state
                    .blocks
                    .iter()
                    .any(|block| match block.block_retention {
                        SegmentRetention::Complete(ingest_time) => binding.contains(ingest_time),
                        SegmentRetention::Empty | SegmentRetention::Unavailable => true,
                    })
            {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            }
            drop(state);
            execution
                .complete_empty_compaction_and_persist(coordinator, self.catalog)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
            return Ok(CompactionPublication {
                input_segments: 0,
                output_segments: 0,
            });
        }
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for block in &blocks {
            let metadata = metadata
                .iter()
                .find(|metadata| {
                    metadata.id == block.source_segment && metadata.state == SegmentState::Sealed
                })
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
            let candidate =
                super::retention_publication::metadata_binding(&self.storage, *metadata)?;
            if !selected.contains(&candidate) {
                selected.push(candidate);
            }
        }
        selected.sort_unstable();
        if selected
            .iter()
            .any(|input| !execution.task().inputs().contains(input))
            || !execution.task().outputs().is_empty()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let mut record = None;
        for bytes in basis.plaintext_objects() {
            if crate::maintenance::durable_task_record_identity(bytes)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?
                == Some(execution.task().identity())
                && record.replace(bytes).is_some()
            {
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            }
        }
        let record =
            record.ok_or_else(|| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        let completion = execution
            .prepare_running_compaction_completion(coordinator, record)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        let terminal = completion
            .catalog_object()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        let result = self.compact_sealed_with_cancellation_inner(
            blocks,
            preparation,
            is_cancelled,
            Some((execution.task().identity(), terminal)),
        );
        match result {
            Ok(publication) => {
                completion
                    .install(coordinator)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
                Ok(publication)
            },
            Err(failure) => {
                if failure.completion_state()
                    == super::LedgerCompletionState::RejectedBeforeMutation
                {
                    completion
                        .discard(coordinator)
                        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
                }
                Err(failure)
            },
        }
    }

    /// Reconciles one same-dispatch Compaction after a post-commit
    /// acknowledgement failure. The terminal PMTC bytes are reconstructed from
    /// the still-running dispatch and must exactly match the sole durable
    /// successor record; no publication is retried here.
    pub fn reconcile_ambiguous_compaction_completion(
        &self,
        blocks: &[CompactionBlock],
        coordinator: &crate::MaintenanceCoordinator,
        execution: &crate::MaintenanceExecution<'_>,
    ) -> Result<(), LedgerFailure> {
        if execution.task().class() != crate::MaintenanceTaskClass::Compaction {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        if blocks.is_empty()
            || blocks.len() > MAX_COMPACTION_BLOCKS
            || blocks
                .windows(2)
                .any(|pair| pair[0].position >= pair[1].position || pair[0].scope != self.scope)
            || blocks.last().is_some_and(|block| block.scope != self.scope)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let binding = crate::CompactionBinding::from_checkpoint(execution.task_checkpoint())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        if binding.scope()
            != crate::MaintenanceScope::segment(
                self.scope.tenant_id(),
                self.scope.signal_kind(),
                self.scope.shard_id(),
            )
            || blocks
                .iter()
                .any(|block| !binding.contains(block.ingest_time))
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let metadata = self.storage.catalog_segments(&basis, self.scope)?;
        if blocks.iter().any(|block| {
            metadata.iter().any(|candidate| {
                candidate.id == block.source_segment && candidate.state != SegmentState::Retired
            })
        }) {
            return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
        }
        let recovered = reconstruct(
            &self.storage,
            &metadata,
            &self.protection,
            self.catalog.instance(),
            RecoveryMode::Observe,
        )?;
        for expected in blocks {
            let matches = recovered
                .blocks
                .iter()
                .filter(|candidate| {
                    candidate.identity() == expected.identity
                        && candidate.position() == expected.position
                        && candidate.payload() == expected.payload.as_slice()
                        && candidate.content_digest().ok() == Some(expected.content_digest)
                        && candidate
                            .authenticate_ingest_time(expected.ingest_time.instant())
                            .is_ok()
                })
                .count();
            if matches != 1 {
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            }
        }
        let mut record = None;
        for bytes in basis.plaintext_objects() {
            if crate::maintenance::durable_task_record_identity(bytes)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?
                == Some(execution.task().identity())
                && record.replace(bytes).is_some()
            {
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            }
        }
        let record =
            record.ok_or_else(|| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        let completion = execution
            .reconcile_running_compaction_completion(coordinator, record)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        completion
            .install_reconciled(coordinator)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let retained_capacity = retained_claim(recovered.retained_bytes, recovered.blocks.len())?;
        state
            .retained_capacity
            .try_resize_preserving_capacity(retained_capacity)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        state.blocks = recovered.blocks;
        state.retained_bytes = recovered.retained_bytes;
        state.frontier = recovered.frontier;
        state.poisoned = false;
        Ok(())
    }

    fn compact_sealed_with_cancellation_inner<F>(
        &self,
        mut blocks: Vec<CompactionBlock>,
        preparation: CompactionPreparation<'kernel>,
        is_cancelled: F,
        terminal: Option<(crate::MaintenanceTaskId, crate::CatalogObject)>,
    ) -> Result<CompactionPublication, LedgerFailure>
    where
        F: Fn() -> bool,
    {
        if blocks.is_empty() || blocks.len() > MAX_COMPACTION_BLOCKS {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        if preparation.scope != self.scope
            || preparation.catalog_instance != self.catalog.instance()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        if let Some(capacity) = preparation.capacity.as_ref() {
            if preparation.coordinator_admitted
                || !capacity.belongs_to(self.authority.governor())
                || !capacity.authorizes_compaction(self.scope.tenant_id())
            {
                return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
            }
        } else if !preparation.coordinator_admitted {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        if blocks.iter().any(|block| block.scope != self.scope) {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        blocks.sort_unstable_by_key(|block| block.position);
        if blocks.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_none_or(|(first, second)| first.position >= second.position)
        }) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }

        let payload_bytes = blocks.iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.payload.len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
        })?;
        if blocks.len() > preparation.maximum_blocks
            || payload_bytes > preparation.maximum_payload_bytes
        {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        let _capacity = preparation.capacity;
        if is_cancelled() {
            return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        state.require_healthy()?;
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let catalog_is_stale = match preparation.retention_policy {
            Some(expected_policy) => {
                basis.retention_policy(expected_policy.signal_kind())? != expected_policy
            },
            None => {
                basis.identity() != preparation.catalog_identity
                    || basis.number() != preparation.catalog_generation
            },
        };
        if catalog_is_stale
            || state.frontier != preparation.frontier
            || snapshot_source_digest_from_blocks(self.scope, state.frontier, &state.blocks)?
                != preparation.source_digest
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let current_metadata = self
            .storage
            .catalog_segments(&basis, self.scope)
            .map_err(|failure| LedgerFailure::new(failure.code()))?;
        let mut selected_segments = Vec::new();
        selected_segments
            .try_reserve_exact(blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        for block in &blocks {
            let Some(source) = state.blocks.iter().find(|candidate| {
                candidate.segment_id() == block.source_segment
                    && candidate.identity() == block.identity
                    && candidate.position() == block.position
            }) else {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            };
            if source.payload() != block.payload.as_slice()
                || source.content_digest()? != block.content_digest
            {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            }
            source
                .authenticate_ingest_time(block.ingest_time.instant())
                .map_err(|failure| LedgerFailure::new(failure.code()))?;
            let Some(metadata) = current_metadata
                .iter()
                .find(|metadata| metadata.id == block.source_segment)
            else {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            };
            if metadata.state != SegmentState::Sealed {
                return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
            }
            if !selected_segments.contains(&block.source_segment) {
                selected_segments.push(block.source_segment);
            }
        }

        for segment in &selected_segments {
            let expected = state
                .blocks
                .iter()
                .filter(|block| block.segment_id() == *segment)
                .count();
            let supplied = blocks
                .iter()
                .filter(|block| block.source_segment == *segment)
                .count();
            if expected != supplied {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            }
        }

        let runs = contiguous_runs(&blocks)?;
        let run_count = runs.len();
        let mut proposal = current_metadata;
        proposal
            .try_reserve_exact(run_count)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(runs.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let mut output_blocks = Vec::new();
        output_blocks
            .try_reserve_exact(blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let volume = self
            .authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        let mut output_storage = LedgerStorage::open(volume)?;
        let mut durable_output_mutated = false;
        for run in runs {
            if is_cancelled() {
                if durable_output_mutated
                    && let Err(cleanup_failure) = discard_outputs(&output_storage, &outputs)
                {
                    state.poisoned = true;
                    return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                }
                return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
            }
            let first = run
                .first()
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::InvalidInput))?;
            let base = position_before(first.position)?;
            let metadata = fresh_metadata(self.scope, base)?;
            let key = match output_storage.create_active(
                metadata,
                &self.protection,
                self.catalog.instance(),
            ) {
                Ok(key) => key,
                Err(failure) => {
                    let cleanup = output_storage
                        .discard_unpublished(metadata)
                        .and_then(|()| discard_outputs(&output_storage, &outputs));
                    if let Err(cleanup_failure) = cleanup {
                        state.poisoned = true;
                        return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                    }
                    return Err(failure);
                },
            };
            durable_output_mutated = true;
            let written = match write_run(&output_storage, &key, metadata.id, &run, &is_cancelled) {
                Ok(written) => written,
                Err(failure) => {
                    let cleanup = output_storage
                        .discard_unpublished(metadata)
                        .and_then(|()| discard_outputs(&output_storage, &outputs));
                    if let Err(cleanup_failure) = cleanup {
                        state.poisoned = true;
                        return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                    }
                    return Err(after_output_creation(failure));
                },
            };
            outputs.push(SegmentMetadata {
                state: SegmentState::Sealed,
                ..metadata
            });
            output_blocks.extend(written);
        }

        let compaction_frontier = blocks
            .last()
            .map(|block| block.position)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        for candidate in proposal.iter_mut() {
            if selected_segments.contains(&candidate.id) {
                // Every retired input is a continuity marker after the
                // replacement's complete frontier. Keeping per-input
                // positions would make reconstruction observe a retired
                // marker behind the replacement output.
                candidate.base_position = compaction_frontier;
                candidate.state = SegmentState::Retired;
            }
        }
        proposal.extend(outputs.iter().copied());
        if is_cancelled() {
            let cleanup = discard_outputs(&output_storage, &outputs);
            if let Err(cleanup_failure) = cleanup {
                state.poisoned = true;
                return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
            }
            return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
        }
        let published = match terminal {
            Some((identity, record)) => publish_exact_scope_segments_with_task_replacement(
                self.catalog,
                &basis,
                &output_storage,
                self.scope,
                &proposal,
                identity,
                record,
            ),
            None => publish_segments(self.catalog, &basis, &output_storage, self.scope, &proposal),
        };
        let published = match published {
            Ok(published) => published,
            Err(failure)
                if failure.completion_state()
                    == super::LedgerCompletionState::RejectedBeforeMutation =>
            {
                if let Err(cleanup_failure) = discard_outputs(&output_storage, &outputs) {
                    state.poisoned = true;
                    return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                }
                return Err(failure);
            },
            Err(failure) => {
                // The publication helper has already reconciled any durable
                // successor. A remaining ambiguous result must retain every
                // output until restart can determine whether that successor
                // was visible to a snapshot.
                state.poisoned = true;
                return Err(failure);
            },
        };
        for output in &outputs {
            if is_cancelled() {
                state.poisoned = true;
                return Err(LedgerFailure::ambiguous(LedgerFailureCode::Cancelled));
            }
            if let Err(failure) = output_storage.seal(*output) {
                state.poisoned = true;
                return Err(LedgerFailure::ambiguous(failure.code()));
            }
            if is_cancelled() {
                state.poisoned = true;
                return Err(LedgerFailure::ambiguous(LedgerFailureCode::Cancelled));
            }
        }

        state
            .blocks
            .retain(|block| !selected_segments.contains(&block.segment_id()));
        state.blocks.extend(output_blocks);
        state.blocks.sort_unstable_by_key(CommittedBlock::position);
        drop(published);
        Ok(CompactionPublication {
            input_segments: selected_segments.len(),
            output_segments: outputs.len(),
        })
    }
}

fn maintenance_source_manifest_digest(
    scope: super::SegmentScope,
    inputs: &[crate::MaintenanceObjectId],
) -> Result<[u8; 32], LedgerFailure> {
    if inputs.is_empty() {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    let mut digest = Sha256::new();
    digest.update(scope.tenant_id().to_bytes());
    digest.update([match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    }]);
    digest.update(scope.shard_id().value().to_be_bytes());
    for input in inputs {
        digest.update(input.to_bytes());
    }
    Ok(digest.finalize().into())
}

fn compaction_source_manifest_and_bounds(
    storage: &super::LedgerStorage,
    metadata: &[SegmentMetadata],
    protection: &super::SegmentProtectionKey,
    instance: crate::InstanceId,
) -> Result<(Vec<crate::MaintenanceObjectId>, usize, usize), LedgerFailure> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(crate::maintenance::MAX_TASK_OBJECTS)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut source_bytes = 0_usize;
    let mut source_blocks = 0_usize;
    for source in metadata
        .iter()
        .filter(|candidate| candidate.state == SegmentState::Sealed)
    {
        let Some((bytes, blocks)) =
            storage.sealed_compaction_source_bound(*source, protection, instance)?
        else {
            continue;
        };
        inputs.push(super::retention_publication::metadata_binding(
            storage, *source,
        )?);
        source_bytes = source_bytes
            .checked_add(bytes)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        source_blocks = source_blocks
            .checked_add(blocks)
            .filter(|count| *count <= MAX_COMPACTION_BLOCKS)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    }
    inputs.sort_unstable();
    if inputs.is_empty() || inputs.len() > crate::maintenance::MAX_TASK_OBJECTS {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    Ok((inputs, source_bytes, source_blocks))
}

fn contiguous_runs(blocks: &[CompactionBlock]) -> Result<Vec<Vec<CompactionBlock>>, LedgerFailure> {
    let mut runs = Vec::new();
    runs.try_reserve_exact(blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    for block in blocks {
        let append = runs.last_mut().filter(|run: &&mut Vec<CompactionBlock>| {
            run.last().is_some_and(|previous| {
                previous
                    .position
                    .value()
                    .checked_add(1)
                    .is_some_and(|next| next == block.position.value())
            })
        });
        if let Some(run) = append {
            run.try_reserve(1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
            run.push(try_clone_block(block)?);
        } else {
            let mut run = Vec::new();
            run.try_reserve(1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
            run.push(try_clone_block(block)?);
            runs.push(run);
        }
    }
    Ok(runs)
}

fn snapshot_source_digest(snapshot: &super::LedgerSnapshot<'_>) -> Result<[u8; 32], LedgerFailure> {
    source_digest(snapshot.scope(), snapshot.frontier(), snapshot.blocks())
}

fn snapshot_source_digest_from_blocks(
    scope: super::SegmentScope,
    frontier: positron_domain::routing::CommitPosition,
    blocks: &[CommittedBlock],
) -> Result<[u8; 32], LedgerFailure> {
    source_digest(scope, frontier, blocks)
}

fn source_digest(
    scope: super::SegmentScope,
    frontier: positron_domain::routing::CommitPosition,
    blocks: &[CommittedBlock],
) -> Result<[u8; 32], LedgerFailure> {
    let mut digest = Sha256::new();
    digest.update(b"positron-compaction-inputs-v1");
    digest.update(scope.tenant_id().to_bytes());
    digest.update([match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    }]);
    digest.update(scope.shard_id().value().to_be_bytes());
    digest.update(frontier.value().to_be_bytes());
    digest.update(
        u64::try_from(blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for block in blocks {
        digest.update(block.segment_id().to_bytes());
        digest.update(block.identity().to_bytes());
        digest.update(block.position().value().to_be_bytes());
        digest.update(block.content_digest()?);
        digest.update(
            u64::try_from(block.payload().len())
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?
                .to_be_bytes(),
        );
    }
    Ok(digest.finalize().into())
}

fn position_before(
    position: positron_domain::routing::CommitPosition,
) -> Result<positron_domain::routing::CommitPosition, LedgerFailure> {
    let value = position.value();
    if value == 0 {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    let previous = value
        .checked_sub(1)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if previous == 0 {
        Ok(positron_domain::routing::CommitPosition::origin())
    } else {
        positron_domain::routing::CommitPosition::origin()
            .advance_by(
                NonZeroU64::new(previous)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
    }
}

fn write_run(
    storage: &LedgerStorage,
    key: &crate::data_protection::ObjectDataKey,
    segment: super::SegmentId,
    blocks: &[CompactionBlock],
    is_cancelled: &impl Fn() -> bool,
) -> Result<Vec<CommittedBlock>, LedgerFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut retention = SegmentRetention::Empty;
    for (sequence, block) in blocks.iter().enumerate() {
        if is_cancelled() {
            return Err(LedgerFailure::post_mutation(LedgerFailureCode::Cancelled));
        }
        let sequence = u64::try_from(sequence)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        retention = retention.append_block(SegmentRetention::Complete(block.ingest_time));
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve_exact(
                25_usize
                    .checked_add(block.payload.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        plaintext.extend_from_slice(&block.identity.to_bytes());
        plaintext.push(2);
        plaintext.extend_from_slice(&block.ingest_time.instant().value().to_be_bytes());
        plaintext.extend_from_slice(&block.payload);
        let context = key
            .object
            .frame(
                SegmentFramePurpose::StoreBlock,
                FrameSequence::new(
                    sequence
                        .checked_add(1)
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                ),
            )
            .map_err(super::map_frame_failure)?;
        let limits = FrameLimits::new(MAX_ENCODED_FRAME_BYTES).map_err(super::map_frame_failure)?;
        let frame_bytes = DataProtection::protected_frame_length(plaintext.len(), limits)
            .map_err(super::map_frame_failure)?;
        let authenticator = storage
            .append_and_commit(
                key,
                NextFrontier {
                    sequence,
                    position: block.position,
                    segment_retention: retention,
                },
                frame_bytes,
                || {
                    DataProtection::protect_frame(key, context, &plaintext, limits)
                        .map_err(super::map_frame_failure)
                },
                || Ok(()),
            )
            .map_err(map_append_failure)?;
        if is_cancelled() {
            return Err(LedgerFailure::post_mutation(LedgerFailureCode::Cancelled));
        }
        let payload = try_clone_bytes(&block.payload)?;
        output.push(CommittedBlock {
            identity: block.identity,
            position: block.position,
            payload,
            content_digest: block.content_digest,
            segment,
            frontier_authenticator: authenticator,
            block_retention: SegmentRetention::Complete(block.ingest_time),
        });
    }
    Ok(output)
}

fn try_clone_block(block: &CompactionBlock) -> Result<CompactionBlock, LedgerFailure> {
    Ok(CompactionBlock {
        scope: block.scope,
        source_segment: block.source_segment,
        identity: block.identity,
        position: block.position,
        payload: try_clone_bytes(&block.payload)?,
        content_digest: block.content_digest,
        ingest_time: block.ingest_time,
    })
}

fn try_clone_bytes(bytes: &[u8]) -> Result<Vec<u8>, LedgerFailure> {
    let mut clone = Vec::new();
    clone
        .try_reserve_exact(bytes.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    clone.extend_from_slice(bytes);
    Ok(clone)
}

fn map_append_failure(failure: AppendFailure) -> LedgerFailure {
    match failure {
        AppendFailure::RejectedBeforeMutation(failure) | AppendFailure::SegmentMutated(failure) => {
            failure
        },
    }
}

fn after_output_creation(failure: LedgerFailure) -> LedgerFailure {
    if failure.code() == LedgerFailureCode::Cancelled {
        return LedgerFailure::new(LedgerFailureCode::Cancelled);
    }
    match failure.completion_state() {
        super::LedgerCompletionState::RejectedBeforeMutation => {
            LedgerFailure::post_mutation(failure.code())
        },
        super::LedgerCompletionState::RecoveryRequired
        | super::LedgerCompletionState::CommitAmbiguous => failure,
    }
}

fn discard_outputs(
    storage: &LedgerStorage,
    outputs: &[SegmentMetadata],
) -> Result<(), LedgerFailure> {
    for metadata in outputs {
        storage.discard_unpublished(*metadata)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_before_rejects_the_origin_position() {
        let failure = position_before(positron_domain::routing::CommitPosition::origin())
            .expect_err("the origin has no predecessor");
        assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
    }
}
