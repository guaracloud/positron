use positron_governance::AuthorizedContext;
use positron_kernel::{LedgerFailureCode, SnapshotLeaseId};
use std::sync::Arc;

use crate::cursor;
use crate::execution_state::{initial_state, merge_durable_usage, validate_authorization};
use crate::execution_support::charge_work;
use crate::execution_support::map_ledger_failure;
use crate::{PlannedQuery, QueryCursor, QueryFailure, QueryFailureCode, QueryService, QueryStream};

use super::resources::ExecutionResources;

const MAX_RESUME_CATALOG_RETRIES: u8 = 1;

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn execute(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.execute_inner(query, None)
    }

    /// Executes against one immutable tenant schema view. The view is used
    /// eagerly and is never retained by the returned materialized stream.
    pub fn execute_with_schema(
        &self,
        query: PlannedQuery<'kernel>,
        schema: &positron_signals::SchemaCatalog,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        self.execute_inner(query, Some(schema))
    }

    fn execute_inner(
        &self,
        query: PlannedQuery<'kernel>,
        schema: Option<&positron_signals::SchemaCatalog>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let (tenant, catalog_identity, _) = self.current_query_catalog(query.context)?;
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        if !query.plan.has_total_limit() {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        let now = self.observe_planned(&query)?;
        let expiry = query
            .started_at
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        if now >= expiry {
            return Err(QueryFailure::budget_exhausted(
                crate::QueryBudgetDimension::WallSeconds,
            ));
        }
        // PlannedQuery still owns its admitted CPU reservation while the
        // immutable lease snapshot is constructed.
        let lease = self
            .ledger
            .create_snapshot_lease_for_at_catalog(
                now,
                remaining_ttl(now, expiry)?,
                catalog_identity,
            )
            .map_err(map_ledger_failure)?;
        let (state, reservation) =
            initial_state(query, lease.snapshot(), tenant, expiry, lease.identity());
        let limit = state.plan.limit();
        let resources = ExecutionResources::new(reservation, lease.identity(), lease.usage());
        self.run_page(state, lease.snapshot(), limit, false, schema, resources)
    }

    pub fn execute_page(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let (tenant, catalog_identity, _) = self.current_query_catalog(query.context)?;
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        if !query.plan.has_total_limit() {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        if self.batch_limit == 0 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        let now_seconds = self.observe_planned(&query)?;
        let expiry = query
            .started_at
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        if now_seconds >= expiry {
            return Err(QueryFailure::budget_exhausted(
                crate::QueryBudgetDimension::WallSeconds,
            ));
        }
        // PlannedQuery still owns its admitted CPU reservation while the
        // immutable lease snapshot is constructed.
        let lease = self
            .ledger
            .create_snapshot_lease_for_at_catalog(
                now_seconds,
                remaining_ttl(now_seconds, expiry)?,
                catalog_identity,
            )
            .map_err(map_ledger_failure)?;
        let (state, reservation) =
            initial_state(query, lease.snapshot(), tenant, expiry, lease.identity());
        let resources = ExecutionResources::new(reservation, lease.identity(), lease.usage());
        self.run_page(
            state,
            lease.snapshot(),
            self.batch_limit,
            true,
            None,
            resources,
        )
    }

    pub fn resume(
        &self,
        context: AuthorizedContext,
        cursor: &QueryCursor,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        let (tenant, mut catalog_identity, mut catalog_generation) =
            self.current_query_catalog(context)?;
        let mut state = cursor::decode_for_admission(&self.ledger.control_tokens(), cursor)?;
        validate_authorization(
            state.principal,
            state.tenant,
            state.authorization_generation,
            context.principal_id(),
            tenant,
            context.authorization_generation(),
        )?;
        let now_seconds = self.now()?;
        if now_seconds < state.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        let resume_elapsed = now_seconds - state.last_observed_at;
        if now_seconds >= state.expiry {
            return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
        }
        let lease_id = SnapshotLeaseId::new(state.lease_identity)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let reservation = self.reserve_query(tenant, state.budget)?;
        // Establish the bounded durable attempt marker before reconstructing
        // source/plans, so failures after admission still have a lease-owned
        // usage record to charge and clean up.
        let mut lease = {
            let mut retries = 0;
            loop {
                match self.ledger.resume_snapshot_lease_with_marker_at_catalog(
                    lease_id,
                    now_seconds,
                    state.sequence,
                    state.prior_digest,
                    catalog_identity,
                    catalog_generation,
                ) {
                    Ok(lease) => break lease,
                    Err(failure)
                        if failure.code() == LedgerFailureCode::StaleGeneration
                            && retries < MAX_RESUME_CATALOG_RETRIES =>
                    {
                        let refreshed = self.current_query_catalog(context).map_err(|failure| {
                            if failure.code() == QueryFailureCode::Unauthorized {
                                QueryFailure::new(QueryFailureCode::AuthorizationChanged)
                            } else {
                                failure
                            }
                        })?;
                        catalog_identity = refreshed.1;
                        catalog_generation = refreshed.2;
                        retries += 1;
                    },
                    Err(failure) => return Err(map_ledger_failure(failure)),
                }
            }
        };
        merge_durable_usage(&mut state, lease.usage());
        if state.physical_elapsed_wall_seconds < state.budget.wall_seconds() {
            state.physical_elapsed_wall_seconds = state
                .physical_elapsed_wall_seconds
                .checked_add(resume_elapsed)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        }
        let attempt = match lease.take_attempt() {
            Some(attempt) => attempt,
            None => {
                self.ledger
                    .release_snapshot_lease(lease.identity())
                    .map_err(map_ledger_failure)?;
                return Err(QueryFailure::new(QueryFailureCode::Internal));
            },
        };
        let resources =
            ExecutionResources::with_attempt(reservation, lease.identity(), lease.usage(), attempt);
        let planning_memory =
            crate::planning_memory::PlanningMemory::new(state.budget.memory_bytes());
        let source_length = match cursor::source_length(cursor) {
            Ok(length) => length,
            Err(failure) => {
                return Err(resources.fail_during_resume_planning(self.ledger, &state, failure));
            },
        };
        let source_reservation = match planning_memory.reserve(source_length) {
            Ok(reservation) => reservation,
            Err(failure) => {
                return Err(resources.fail_during_resume_planning(self.ledger, &state, failure));
            },
        };
        let decoded = match cursor::decode(&self.ledger.control_tokens(), cursor) {
            Ok(decoded) => decoded,
            Err(failure) => {
                return Err(resources.fail_during_resume_planning(self.ledger, &state, failure));
            },
        };
        state.source = decoded.source;
        state.language = decoded.language;
        if let Err(failure) = self.reconstruct_plan(&mut state, &planning_memory) {
            return Err(resources.fail_during_resume_planning(self.ledger, &state, failure));
        }
        drop(source_reservation);
        if lease.snapshot().catalog_identity().to_bytes() != state.catalog_identity
            || lease.snapshot().catalog_generation() != state.catalog_generation
            || lease.snapshot().frontier().value() != state.frontier
        {
            return Err(resources.fail_before_stream(
                self.ledger,
                &state,
                QueryFailure::new(QueryFailureCode::InvalidCursor),
            ));
        }
        let mut state = state;
        state.resume_count = lease.resume_count();
        state.repeated_batch_count = lease.repeated_batch_count();
        state.last_observed_at = now_seconds;
        self.run_page(
            state,
            lease.snapshot(),
            self.batch_limit,
            true,
            None,
            resources,
        )
    }

    fn reconstruct_plan(
        &self,
        state: &mut cursor::CursorState,
        memory: &crate::planning_memory::PlanningMemory,
    ) -> Result<(), QueryFailure> {
        let (Some(source), Some(language)) = (state.source.clone(), state.language) else {
            return Ok(());
        };
        let source = std::str::from_utf8(&source)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let (plan, plan_reservation, compile_work) =
            self.compile_plan(source, language, memory, state.budget)?;
        charge_work(state, self.work_units(crate::QueryWorkStage::Parse)?)?;
        if compile_work > 0 {
            let unit = self.work_units(crate::QueryWorkStage::Parse)?;
            charge_work(
                state,
                unit.checked_mul(compile_work).ok_or_else(|| {
                    QueryFailure::budget_exhausted(crate::QueryBudgetDimension::CpuWorkUnits)
                })?,
            )?;
        }
        let digest = plan.canonical_digest(&self.ledger.control_tokens())?;
        if state.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        if digest != state.plan_digest {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        drop(plan_reservation);
        state.plan = Arc::new(plan);
        Ok(())
    }

    fn observe_planned(&self, query: &PlannedQuery<'_>) -> Result<u64, QueryFailure> {
        let now = self.now()?;
        if now < query.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        Ok(now)
    }
}

fn remaining_ttl(now: u64, expiry: u64) -> Result<std::num::NonZeroU64, QueryFailure> {
    expiry
        .checked_sub(now)
        .and_then(std::num::NonZeroU64::new)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::SnapshotExpired))
}
