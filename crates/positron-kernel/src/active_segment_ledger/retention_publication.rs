use std::collections::BTreeSet;

use super::format::SegmentState;
use super::publication::{RetentionPublication, publish_retention_with_tasks};
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode};
use crate::maintenance::RetentionPublicationBinding;
use crate::{
    MaintenanceCoordinator, MaintenanceExecution, MaintenancePreconditions, MaintenanceScope,
    MaintenanceTask, MaintenanceTaskClass, MaintenanceTaskId, MaintenanceTrigger,
    RecoveryWorkClaim, RecoveryWorkKind, ResourceDimension, ResourceReservation,
};

mod plan;
mod proof;

use plan::{metadata_binding, retention_publication_plan, task_bindings, task_identity};
pub(super) use proof::retention_publication_claim;
use proof::{durable_task_record, retention_publication_frontier_bound};

/// An admitted retention-publication descriptor. Its preparation reservation
/// covers metadata planning and the one durable task submission, then drops
/// before a later execution receives its own Recovery grant.
#[derive(Debug)]
pub struct RetentionPublicationPreparation<'kernel> {
    capacity: ResourceReservation<'kernel>,
    task: MaintenanceTask,
    frontier: crate::IngestTime,
}

impl RetentionPublicationPreparation<'_> {
    #[must_use]
    pub const fn task(&self) -> &MaintenanceTask {
        &self.task
    }

    pub fn submit_and_persist(
        self,
        coordinator: &MaintenanceCoordinator,
        catalog: &crate::Catalog<'_>,
        submitted_at: u64,
    ) -> Result<MaintenanceTask, LedgerFailure> {
        let tenant = self
            .task
            .scope()
            .tenant_id()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch))?;
        if !self.capacity.authorizes_retention_publication(tenant) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let checkpoint =
            crate::maintenance::retention_publication_frontier_checkpoint(self.frontier)
                .map_err(map_maintenance_failure)?;
        coordinator
            .submit_retention_publication_and_persist(
                catalog,
                self.task.clone(),
                checkpoint,
                submitted_at,
            )
            .map_err(map_maintenance_failure)?;
        Ok(self.task)
    }
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Builds the sole age-derived retention publication descriptor from the
    /// sealed metadata and authenticated lifecycle clock. Callers cannot
    /// provide object bindings, capacity, policy, or a clock value.
    pub fn prepare_retention_publication(
        &self,
    ) -> Result<RetentionPublicationPreparation<'kernel>, LedgerFailure> {
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
        let capacity = self
            .authority
            .recovery()
            .reserve(
                RecoveryWorkClaim::tenant(
                    self.scope.tenant_id(),
                    RecoveryWorkKind::Retention,
                    retention_publication_claim()?,
                )
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let frontier = retention_time
            .destructive_ingest_time(self.scope, state.retention_frontier)
            .map_err(super::map_retention_time_failure)?;
        let plan = retention_publication_plan(self, &basis, &state, frontier)?;
        if plan.retired.is_empty() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let (inputs, outputs) = task_bindings(&plan.retired)?;
        let identity = task_identity(inputs[0], 0x00)?;
        let task = MaintenanceTask::with_contract(
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
            retention_publication_claim()?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        Ok(RetentionPublicationPreparation {
            capacity,
            task,
            frontier: plan.frontier,
        })
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
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let durable_record = durable_task_record(&basis, execution.task().identity())?;
        let expected = execution.task();
        let reclamation_identity = expected
            .outputs()
            .first()
            .copied()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StaleGeneration))
            .and_then(|output| task_identity(output, 0xa5))?;
        let reclamation_record = match durable_task_record(&basis, reclamation_identity) {
            Ok(record) => Some(record),
            Err(failure) if failure.code() == LedgerFailureCode::RecoveryRequired => None,
            Err(failure) => return Err(failure),
        };
        if let Some(reclamation_record) = reclamation_record {
            let expected_frontier =
                retention_publication_frontier_bound(coordinator, execution.task().identity())?;
            let completion = execution
                .reconcile_running_retention_publication_completion(
                    coordinator,
                    durable_record,
                    reclamation_record,
                )
                .map_err(map_maintenance_failure)?;
            let metadata = self.storage.catalog_segments(&basis, self.scope)?;
            let outputs = expected.outputs().iter().copied().collect::<BTreeSet<_>>();
            let retired = metadata
                .iter()
                .filter(|metadata| metadata.state == SegmentState::Retired)
                .try_fold(BTreeSet::new(), |mut retired, metadata| {
                    let binding = metadata_binding(&self.storage, *metadata)?;
                    if outputs.contains(&binding) {
                        retired.insert(metadata.id);
                    }
                    Ok::<_, LedgerFailure>(retired)
                })?;
            let recovered_frontier = super::retention_frontier::recover(&basis, self.scope)?;
            if retired.len() != outputs.len()
                || recovered_frontier.is_none_or(|frontier| frontier < expected_frontier)
                || !retention_time
                    .catalog_anchor_subsumes_observed(&basis, expected_frontier)
                    .map_err(super::map_retention_time_failure)?
            {
                return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
            }
            retention_time
                .recover_catalog_anchor(&basis)
                .map_err(super::map_retention_time_failure)?;
            completion
                .install_reconciled(coordinator)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
            state
                .blocks
                .retain(|block| !retired.contains(&block.segment));
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
            state.retention_frontier = recovered_frontier;
            state.retention_readiness = super::state::RetentionReadiness::TrustedPersisted;
            return Ok(reclamation_identity);
        }
        if coordinator
            .status(expected.identity())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?
            .cancellation_requested()
        {
            execution
                .cancel_running_retention_publication_and_persist(coordinator, self.catalog)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
            return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
        }
        let durable_frontier =
            retention_publication_frontier_bound(coordinator, expected.identity())?;
        let mut clock_anchor = retention_time
            .stage_catalog_anchor()
            .map_err(super::map_retention_time_failure)?;
        let observed_frontier = clock_anchor
            .destructive_ingest_time(self.scope, state.retention_frontier)
            .map_err(super::map_retention_time_failure)?;
        if observed_frontier < durable_frontier {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let expected_claim = retention_publication_claim()?;
        if !ResourceDimension::ALL.iter().all(|dimension| {
            expected_claim.get(*dimension) <= execution.reservation().granted().get(*dimension)
        }) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let plan = retention_publication_plan(self, &basis, &state, durable_frontier)?;
        if plan.retired.is_empty() {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let (inputs, outputs) = task_bindings(&plan.retired)?;
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
        let reclamation_identity = task_identity(
            *outputs
                .first()
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StaleGeneration))?,
            0xa5,
        )?;
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
                anchor: observed_frontier,
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
        retention_time
            .recover_catalog_anchor(&latest)
            .map_err(|failure| {
                LedgerFailure::post_mutation(super::map_retention_time_failure(failure).code())
            })?;
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
        if !expected_retired.is_subset(&published_retired) {
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

fn map_maintenance_failure(failure: crate::MaintenanceFailure) -> LedgerFailure {
    let code = match failure {
        crate::MaintenanceFailure::CapacityExceeded
        | crate::MaintenanceFailure::ResourceAdmissionRefused => {
            LedgerFailureCode::ResourceAdmissionRefused
        },
        crate::MaintenanceFailure::CatalogUnavailable => LedgerFailureCode::StorageUnavailable,
        crate::MaintenanceFailure::ConcurrentAccess => LedgerFailureCode::ConcurrentWriter,
        crate::MaintenanceFailure::InvalidInput => LedgerFailureCode::InvalidInput,
        crate::MaintenanceFailure::UnknownTask
        | crate::MaintenanceFailure::InvalidTransition
        | crate::MaintenanceFailure::PreconditionFailed
        | crate::MaintenanceFailure::Paused => LedgerFailureCode::StaleGeneration,
    };
    LedgerFailure::new(code)
}
