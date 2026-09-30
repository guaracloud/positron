use std::collections::BTreeSet;
use std::mem::size_of;

use super::format::SegmentState;
use super::publication::{RetentionPublication, publish_retention_with_tasks};
use super::{ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, SegmentRetention};
use crate::maintenance::RetentionPublicationBinding;
use crate::{
    CatalogObject, MaintenanceCoordinator, MaintenanceExecution, MaintenanceObjectId,
    MaintenancePreconditions, MaintenanceScope, MaintenanceTask, MaintenanceTaskClass,
    MaintenanceTaskId, MaintenanceTrigger, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts,
    ResourceDimension, ResourceReservation,
};

const RETENTION_PUBLICATION_BATCH_ITEMS: u64 = 16;
const MAX_RETENTION_PUBLICATION_SEGMENTS: usize = 16;

/// An admitted retention-publication descriptor. Its preparation reservation
/// covers metadata planning and the one durable task submission, then drops
/// before a later execution receives its own Recovery grant.
#[derive(Debug)]
pub struct RetentionPublicationPreparation<'kernel> {
    capacity: ResourceReservation<'kernel>,
    task: MaintenanceTask,
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
        coordinator
            .submit_and_persist(catalog, self.task.clone(), submitted_at)
            .map_err(map_maintenance_failure)?;
        Ok(self.task)
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
        Ok(RetentionPublicationPreparation { capacity, task })
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
        let expected_claim = retention_publication_claim()?;
        if !ResourceDimension::ALL.iter().all(|dimension| {
            expected_claim.get(*dimension) <= execution.reservation().granted().get(*dimension)
        }) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let plan = retention_publication_plan(self, &basis, &state, frontier)?;
        if plan.retired.is_empty() {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        }
        let (inputs, outputs) = task_bindings(&plan.retired)?;
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

fn retention_publication_claim() -> Result<ResourceAmounts, LedgerFailure> {
    let scanned_metadata = crate::catalog::MAX_CATALOG_OBJECTS
        .checked_mul(size_of::<super::format::SegmentMetadata>())
        .and_then(|bytes| bytes.checked_mul(2));
    let proposed_catalog = crate::catalog::MAX_CATALOG_OBJECTS
        .checked_mul(size_of::<CatalogObject>())
        .and_then(|objects| {
            crate::catalog::MAX_CATALOG_OBJECTS
                .checked_mul(size_of::<super::format::SegmentMetadata>())
                .and_then(|metadata| objects.checked_add(metadata))
        });
    let bindings = MAX_RETENTION_PUBLICATION_SEGMENTS
        .checked_mul(size_of::<MaintenanceObjectId>())
        .and_then(|objects| objects.checked_mul(2));
    let record_bytes = crate::maintenance::retention_publication_record_bytes_bound()
        .map_err(map_maintenance_failure)?;
    let memory = crate::catalog::MAX_CATALOG_TOTAL_BYTES
        .checked_add(
            scanned_metadata
                .zip(proposed_catalog)
                .map(|(scan, proposal)| scan.max(proposal))
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .and_then(|bytes| bytes.checked_add(bindings?))
        .and_then(|bytes| bytes.checked_add(record_bytes))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        u64::try_from(memory).map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        1,
        1,
        0,
        RETENTION_PUBLICATION_BATCH_ITEMS,
        0,
        1,
        1,
        1,
        1,
        0,
    ]))
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
    retired
        .try_reserve_exact(metadata.len().min(MAX_RETENTION_PUBLICATION_SEGMENTS))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    for candidate in metadata
        .iter_mut()
        .filter(|candidate| candidate.state == SegmentState::Sealed)
    {
        if retired.len() == MAX_RETENTION_PUBLICATION_SEGMENTS {
            break;
        }
        let input = metadata_binding(&ledger.storage, *candidate)?;
        let mut latest: Option<crate::IngestTime> = None;
        let mut last_position: Option<positron_domain::routing::CommitPosition> = None;
        let mut has_blocks = false;
        for block in state
            .blocks
            .iter()
            .filter(|block| block.segment == candidate.id)
        {
            has_blocks = true;
            match block.block_retention {
                SegmentRetention::Complete(instant) => {
                    latest = Some(latest.map_or(instant, |current| current.max(instant)));
                    last_position = Some(
                        last_position
                            .map_or(block.position(), |current| current.max(block.position())),
                    );
                },
                SegmentRetention::Empty | SegmentRetention::Unavailable => {
                    return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
                },
            }
        }
        if has_blocks && latest.is_none_or(|instant| instant.instant().value() > cutoff) {
            continue;
        }
        if let Some(position) = last_position {
            candidate.base_position = position;
        }
        candidate.state = SegmentState::Retired;
        let output = metadata_binding(&ledger.storage, *candidate)?;
        retired.push((input, output));
    }
    retired.sort_unstable_by_key(|(input, _)| *input);
    Ok(RetentionPublicationPlan {
        metadata,
        retired,
        frontier,
    })
}

fn task_bindings(
    retired: &[(MaintenanceObjectId, MaintenanceObjectId)],
) -> Result<(Vec<MaintenanceObjectId>, Vec<MaintenanceObjectId>), LedgerFailure> {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    inputs
        .try_reserve_exact(retired.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    outputs
        .try_reserve_exact(retired.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    for (input, output) in retired {
        inputs.push(*input);
        outputs.push(*output);
    }
    inputs.sort_unstable();
    outputs.sort_unstable();
    Ok((inputs, outputs))
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
