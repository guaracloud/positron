use std::collections::BTreeSet;

use super::capacity::retained_claim;
use super::format::SegmentState;
use super::publication::{
    RetentionPublication, publish_exact_scope_segments, publish_retention_with_tasks,
    publish_segments_with_frontier,
};
use super::{
    ActiveSegmentLedger, LedgerCompletionState, LedgerFailure, LedgerFailureCode,
    RetentionEvaluation, RetentionReclamation, SegmentRetention,
};
use crate::maintenance::RetentionPublicationBinding;
use crate::{
    CatalogObject, MaintenanceCoordinator, MaintenanceExecution, MaintenanceObjectId,
    MaintenancePreconditions, MaintenanceScope, MaintenanceTask, MaintenanceTaskClass,
    MaintenanceTaskId, MaintenanceTrigger, ResourceDimension,
};

pub(super) fn commit(
    evaluation: RetentionEvaluation<'_, '_, '_>,
) -> Result<RetentionReclamation, LedgerFailure> {
    let ledger = evaluation.ledger;
    let mut state = ledger
        .state
        .lock()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
    state.require_healthy()?;
    ledger.catalog.refresh_state()?;
    let basis = ledger.catalog.pin()?;
    let current_policy = basis.retention_policy(ledger.scope.signal)?;
    if current_policy != evaluation.policy {
        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
    }
    if state.retention_frontier != evaluation.expected_retention_frontier
        || state.retention_readiness != evaluation.expected_retention_readiness
    {
        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
    }
    if state.blocks != evaluation.blocks {
        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
    }
    let mut metadata = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let mut newly_retired = BTreeSet::new();
    for candidate in metadata
        .iter_mut()
        .filter(|candidate| candidate.state == SegmentState::Sealed)
    {
        let mut segment_blocks = state
            .blocks
            .iter()
            .filter(|block| block.segment == candidate.id)
            .peekable();
        if segment_blocks.peek().is_none() {
            candidate.state = SegmentState::Retired;
            newly_retired.insert(candidate.id);
            continue;
        }
        let mut latest = None;
        for block in segment_blocks {
            match block.block_retention {
                SegmentRetention::Complete(instant) => {
                    latest = Some(
                        latest.map_or(instant, |current: crate::IngestTime| current.max(instant)),
                    );
                },
                SegmentRetention::Empty | SegmentRetention::Unavailable => {
                    return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
                },
            }
        }
        if latest.is_none_or(|latest| latest.instant().value() > evaluation.cutoff.value()) {
            continue;
        }
        // A retired segment no longer participates in reconstruction, so its
        // catalog position carries the authenticated continuity point needed
        // to resume the following segment after a restart.
        candidate.base_position = state
            .blocks
            .iter()
            .filter(|block| block.segment_id() == candidate.id)
            .map(|block| block.position())
            .max()
            .map_or(candidate.base_position, |position| position);
        candidate.state = SegmentState::Retired;
        newly_retired.insert(candidate.id);
    }
    let now = evaluation
        .frontier
        .instant()
        .value()
        .checked_div(1_000_000_000)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let latest = match publish_segments_with_frontier(
        ledger.catalog,
        &basis,
        &ledger.storage,
        &evaluation.clock_anchor,
        ledger.scope,
        &metadata,
        evaluation.frontier,
    ) {
        Ok(latest) => latest,
        Err(failure) => {
            if failure.completion_state() != super::LedgerCompletionState::RejectedBeforeMutation {
                state.poisoned = true;
            }
            return Err(failure);
        },
    };
    evaluation.clock_anchor.commit();
    let latest_metadata = ledger
        .storage
        .catalog_segments(&latest, ledger.scope)
        .map_err(|failure| poison_after_commit(&mut state, failure))?;
    let retired = latest_metadata
        .iter()
        .filter(|candidate| candidate.state == SegmentState::Retired)
        .map(|candidate| candidate.id)
        .collect::<BTreeSet<_>>();
    if !retired.is_empty() {
        state
            .blocks
            .retain(|block| !retired.contains(&block.segment));
        state.retained_bytes = state
            .blocks
            .iter()
            .try_fold(0_usize, |total, block| {
                total.checked_add(block.payload.len())
            })
            .ok_or_else(|| {
                poison_after_commit(
                    &mut state,
                    LedgerFailure::new(LedgerFailureCode::LimitExceeded),
                )
            })?;
        let remaining_capacity = retained_claim(state.retained_bytes, state.blocks.len())
            .map_err(|failure| poison_after_commit(&mut state, failure))?;
        if state
            .retained_capacity
            .try_resize_preserving_capacity(remaining_capacity)
            .is_err()
        {
            state.poisoned = true;
            return Err(LedgerFailure::post_mutation(
                LedgerFailureCode::RecoveryRequired,
            ));
        }
    }
    state.retention_frontier = Some(evaluation.frontier);
    state.retention_readiness = super::state::RetentionReadiness::TrustedPersisted;
    let physically_reclaimed_segments = match reclaim_retired_segments(ledger, now) {
        Ok(reclaimed) => reclaimed,
        Err(failure) => {
            return Err(poison_after_commit(&mut state, failure));
        },
    };
    Ok(RetentionReclamation {
        logically_retired_segments: newly_retired.len(),
        physically_reclaimed_segments,
        evaluated_at: evaluation.frontier.instant(),
    })
}

fn poison_after_commit(
    state: &mut super::state::LedgerState,
    failure: LedgerFailure,
) -> LedgerFailure {
    state.poisoned = true;
    if failure.completion_state() == LedgerCompletionState::RejectedBeforeMutation {
        LedgerFailure::post_mutation(failure.code())
    } else {
        failure
    }
}

fn reclaim_retired_segments(
    ledger: &ActiveSegmentLedger<'_, '_>,
    now: u64,
) -> Result<usize, LedgerFailure> {
    let _barrier = super::snapshot_protection::SnapshotProtection::write_barrier(
        ledger.authority.snapshot_barrier(),
    )?;
    let basis = ledger.catalog.pin()?;
    let metadata = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let leased = super::snapshot_lease::active_segments(&basis, ledger.scope, now)?;
    let registry = ledger.authority.snapshot_protection();
    let mut reclaimable = Vec::new();
    reclaimable
        .try_reserve_exact(metadata.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for candidate in metadata.iter().copied().filter(|candidate| {
        candidate.state == SegmentState::Retired && !leased.contains(&candidate.id)
    }) {
        if !super::snapshot_protection::SnapshotProtection::is_protected(&registry, candidate.id)? {
            reclaimable.push(candidate);
        }
    }
    if reclaimable.is_empty() {
        return Ok(0);
    }
    let mut physically_mutated = false;
    for candidate in &reclaimable {
        match ledger.storage.reclaim_retired(*candidate) {
            Ok(changed) => physically_mutated |= changed,
            Err(failure) if physically_mutated => {
                return Err(LedgerFailure::post_mutation(failure.code()));
            },
            Err(failure) => return Err(failure),
        }
    }
    let basis = ledger
        .catalog
        .pin()
        .map_err(LedgerFailure::from)
        .map_err(|failure| after_physical_reclamation(failure, physically_mutated))?;
    let mut remaining = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| after_physical_reclamation(failure, physically_mutated))?;
    let continuity_marker = reclaimable
        .iter()
        .copied()
        .max_by_key(|candidate| candidate.base_position);
    remaining.retain(|candidate| !reclaimable.iter().any(|retired| retired.id == candidate.id));
    if let Some(marker) = continuity_marker {
        remaining.push(marker);
    }
    publish_exact_scope_segments(
        ledger.catalog,
        &basis,
        &ledger.storage,
        ledger.scope,
        &remaining,
    )
    .map_err(|failure| after_physical_reclamation(failure, physically_mutated))?;
    Ok(reclaimable.len())
}

fn after_physical_reclamation(failure: LedgerFailure, physically_mutated: bool) -> LedgerFailure {
    if physically_mutated {
        LedgerFailure::post_mutation(failure.code())
    } else {
        failure
    }
}

struct RetentionPublicationPlan {
    metadata: Vec<super::format::SegmentMetadata>,
    retired: Vec<(MaintenanceObjectId, MaintenanceObjectId)>,
    frontier: crate::IngestTime,
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Builds the sole age-derived retention publication descriptor from the
    /// sealed metadata and authenticated lifecycle clock. Callers cannot
    /// provide object bindings, capacity, policy, or a clock value.
    pub fn prepare_retention_publication(&self) -> Result<MaintenanceTask, LedgerFailure> {
        let retention_time = self
            .retention_time
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?;
        if !retention_time.is_destructive_authority() {
            return Err(LedgerFailure::new(LedgerFailureCode::ClockUncertain));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        state.require_healthy()?;
        let frontier = retention_time
            .destructive_ingest_time(self.scope, state.retention_frontier)
            .map_err(super::map_retention_time_failure)?;
        let plan = retention_publication_plan(self, &basis, &state, frontier)?;
        if plan.retired.is_empty() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let (inputs, outputs) = task_bindings(&plan.retired);
        let identity = task_identity(inputs[0], 0x00)?;
        let provisional = MaintenanceTask::with_contract(
            identity,
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceScope::segment(
                self.scope.tenant_id(),
                self.scope.signal_kind(),
                self.scope.shard_id(),
            ),
            MaintenanceTrigger::AgeDerived,
            MaintenancePreconditions::new(basis.number(), 1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            inputs.clone(),
            outputs.clone(),
            super::capacity::retention_claim(1, 1)?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let catalog_bytes = catalog_bytes(&basis)?;
        let record_bytes = crate::maintenance::queued_task_record_bytes(&provisional)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let claim = super::capacity::retention_claim(
            state
                .retained_bytes
                .checked_add(catalog_bytes)
                .and_then(|bytes| bytes.checked_add(record_bytes))
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            state
                .blocks
                .len()
                .checked_add(basis.plaintext_object_count())
                .and_then(|items| items.checked_add(1))
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )?;
        MaintenanceTask::with_contract(
            identity,
            MaintenanceTaskClass::RetentionPublication,
            MaintenanceScope::segment(
                self.scope.tenant_id(),
                self.scope.signal_kind(),
                self.scope.shard_id(),
            ),
            MaintenanceTrigger::AgeDerived,
            MaintenancePreconditions::new(basis.number(), 1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            inputs,
            outputs,
            claim,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
    }

    /// Atomically publishes the retired metadata/frontier, the terminal
    /// Publication record, and its bound Reclamation successor. The live
    /// execution's Recovery reservation is checked before any scan and is
    /// never replaced by a second reservation.
    pub fn complete_running_retention_publication_task(
        &self,
        coordinator: &MaintenanceCoordinator,
        execution: &MaintenanceExecution<'_>,
    ) -> Result<MaintenanceTaskId, LedgerFailure> {
        let retention_time = self
            .retention_time
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::ClockUncertain))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        state.require_healthy()?;
        if coordinator
            .status(execution.task().identity())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?
            .cancellation_requested()
        {
            execution
                .complete_and_persist(coordinator, self.catalog, true)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
            return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let durable_record = durable_task_record(&basis, execution.task().identity())?;
        let mut clock_anchor = retention_time
            .stage_catalog_anchor()
            .map_err(super::map_retention_time_failure)?;
        let frontier = clock_anchor
            .destructive_ingest_time(self.scope, state.retention_frontier)
            .map_err(super::map_retention_time_failure)?;
        let plan = retention_publication_plan(self, &basis, &state, frontier)?;
        if plan.retired.is_empty() {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let (inputs, outputs) = task_bindings(&plan.retired);
        let expected = execution.task();
        if expected.class() != MaintenanceTaskClass::RetentionPublication
            || expected.scope()
                != MaintenanceScope::segment(
                    self.scope.tenant_id(),
                    self.scope.signal_kind(),
                    self.scope.shard_id(),
                )
            || expected.trigger() != MaintenanceTrigger::AgeDerived
            || expected.inputs() != inputs
            || expected.outputs() != outputs
            || expected.preconditions().resource_generation() != 1
            || expected.preconditions().catalog_generation() >= basis.number()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let actual = super::capacity::retention_claim(
            state
                .retained_bytes
                .checked_add(catalog_bytes(&basis)?)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            state
                .blocks
                .len()
                .checked_add(basis.plaintext_object_count())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )?;
        if !ResourceDimension::ALL.iter().all(|dimension| {
            actual.get(*dimension) <= execution.reservation().granted().get(*dimension)
        }) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let reclamation_identity = task_identity(outputs[0], 0xa5)?;
        let reclamation = MaintenanceTask::with_contract(
            reclamation_identity,
            MaintenanceTaskClass::RetentionReclamation,
            expected.scope(),
            MaintenanceTrigger::AgeDerived,
            expected.preconditions(),
            outputs.clone(),
            Vec::new(),
            expected.reservations(),
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let completion = execution
            .prepare_running_retention_publication_completion(
                coordinator,
                RetentionPublicationBinding::new(expected, reclamation, durable_record),
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?;
        let additional = match completion.catalog_objects() {
            Ok(objects) => objects,
            Err(_) => {
                completion.discard(coordinator);
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            },
        };
        let mut replaced = BTreeSet::new();
        replaced.insert(completion.publication_identity());
        let latest = match publish_retention_with_tasks(
            self.catalog,
            &basis,
            &self.storage,
            RetentionPublication {
                lifecycle_clock: &clock_anchor,
                scope: self.scope,
                metadata: &plan.metadata,
                frontier: plan.frontier,
                additional,
                replaced_tasks: replaced,
            },
        ) {
            Ok(snapshot) => snapshot,
            Err(failure) => {
                completion.discard(coordinator);
                return Err(failure);
            },
        };
        clock_anchor.commit();
        completion
            .install(coordinator)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
        let latest_metadata = self
            .storage
            .catalog_segments(&latest, self.scope)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        let published_retired = latest_metadata
            .iter()
            .filter(|metadata| metadata.state == SegmentState::Retired)
            .map(|metadata| metadata_binding(&self.storage, *metadata))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_retired = plan
            .retired
            .iter()
            .map(|(_, output)| *output)
            .collect::<BTreeSet<_>>();
        if published_retired != expected_retired {
            state.poisoned = true;
            return Err(LedgerFailure::post_mutation(
                LedgerFailureCode::RecoveryRequired,
            ));
        }
        let retired_segments = plan
            .metadata
            .iter()
            .filter(|metadata| metadata.state == SegmentState::Retired)
            .map(|metadata| metadata.id)
            .collect::<BTreeSet<_>>();
        state
            .blocks
            .retain(|block| !retired_segments.contains(&block.segment));
        state.retained_bytes = state.blocks.iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.payload.len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
        })?;
        let remaining_capacity =
            super::capacity::retained_claim(state.retained_bytes, state.blocks.len())?;
        state
            .retained_capacity
            .try_resize_preserving_capacity(remaining_capacity)
            .map_err(|_| LedgerFailure::post_mutation(LedgerFailureCode::RecoveryRequired))?;
        state.retention_frontier = Some(plan.frontier);
        state.retention_readiness = super::state::RetentionReadiness::TrustedPersisted;
        Ok(reclamation_identity)
    }
}

fn retention_publication_plan(
    ledger: &ActiveSegmentLedger<'_, '_>,
    basis: &crate::CatalogSnapshot,
    state: &super::state::LedgerState<'_>,
    frontier: crate::IngestTime,
) -> Result<RetentionPublicationPlan, LedgerFailure> {
    let policy = basis.retention_policy(ledger.scope.signal)?;
    if policy.instance() != ledger.catalog.instance()
        || policy.tenant() != ledger.scope.tenant
        || policy.signal_kind() != ledger.scope.signal
    {
        return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
    }
    let duration_nanos = policy
        .retention_seconds()
        .get()
        .checked_mul(1_000_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let cutoff = frontier
        .instant()
        .value()
        .checked_sub(duration_nanos)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut metadata = ledger.storage.catalog_segments(basis, ledger.scope)?;
    let mut retired = Vec::new();
    for candidate in metadata
        .iter_mut()
        .filter(|candidate| candidate.state == SegmentState::Sealed)
    {
        let blocks = state
            .blocks
            .iter()
            .filter(|block| block.segment == candidate.id)
            .collect::<Vec<_>>();
        if blocks.is_empty()
            || blocks.iter().any(|block| match block.block_retention {
                SegmentRetention::Complete(instant) => instant.instant().value() > cutoff,
                SegmentRetention::Empty | SegmentRetention::Unavailable => true,
            })
        {
            continue;
        }
        let input = metadata_binding(&ledger.storage, *candidate)?;
        candidate.base_position = blocks
            .iter()
            .map(|block| block.position())
            .max()
            .unwrap_or(candidate.base_position);
        candidate.state = SegmentState::Retired;
        let output = metadata_binding(&ledger.storage, *candidate)?;
        retired.push((input, output));
    }
    Ok(RetentionPublicationPlan {
        metadata,
        retired,
        frontier,
    })
}

fn catalog_bytes(basis: &crate::CatalogSnapshot) -> Result<usize, LedgerFailure> {
    basis.plaintext_objects().try_fold(0_usize, |total, bytes| {
        total
            .checked_add(bytes.len())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
    })
}

fn task_bindings(
    retired: &[(MaintenanceObjectId, MaintenanceObjectId)],
) -> (Vec<MaintenanceObjectId>, Vec<MaintenanceObjectId>) {
    retired.iter().copied().unzip()
}

fn metadata_binding(
    storage: &super::LedgerStorage,
    metadata: super::format::SegmentMetadata,
) -> Result<MaintenanceObjectId, LedgerFailure> {
    MaintenanceObjectId::new(
        CatalogObject::new(storage.metadata_object(metadata))?
            .identity()
            .to_bytes(),
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}

fn task_identity(
    binding: MaintenanceObjectId,
    discriminator: u8,
) -> Result<MaintenanceTaskId, LedgerFailure> {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        binding
            .to_bytes()
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
    );
    bytes[0] ^= discriminator;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    MaintenanceTaskId::new(bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}

fn durable_task_record(
    basis: &crate::CatalogSnapshot,
    identity: MaintenanceTaskId,
) -> Result<&[u8], LedgerFailure> {
    let mut record = None;
    for bytes in basis.plaintext_objects() {
        if crate::maintenance::durable_task_record_identity(bytes)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?
            == Some(identity)
            && record.replace(bytes).is_some()
        {
            return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
        }
    }
    record.ok_or_else(|| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))
}
