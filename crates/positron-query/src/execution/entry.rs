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
    fn fail_after_source_lease(
        &self,
        source_lease: SnapshotLeaseId,
        primary: QueryFailure,
    ) -> QueryFailure {
        match self.ledger.release_snapshot_lease(source_lease) {
            Ok(()) => primary,
            Err(first_cleanup) => {
                let cleanup = map_ledger_failure(first_cleanup);
                match self.ledger.release_snapshot_lease(source_lease) {
                    Ok(()) => crate::failure::stronger_failure(primary, cleanup),
                    Err(retry_cleanup) => crate::failure::stronger_failure(
                        crate::failure::stronger_failure(primary, cleanup),
                        map_ledger_failure(retry_cleanup),
                    ),
                }
            },
        }
    }

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
        // Correlation has two authenticated Signal Store sources. Until the
        // paired-store path admits both snapshots, it must never degrade into
        // the ordinary Log Store executor and present log-only rows as a
        // correlation result.
        if query.plan.is_log_to_trace_correlation() && self.trace_ledger.is_none() {
            return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        }
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
        let trace_ledger = if query.plan.is_log_to_trace_correlation() {
            let trace_ledger = self
                .trace_ledger
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            if trace_ledger.scope().tenant_id() != tenant {
                return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
            }
            if trace_ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Traces {
                return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
            }
            Some(trace_ledger)
        } else {
            None
        };
        // PlannedQuery still owns its admitted CPU reservation while the
        // separately scoped immutable source snapshots are constructed.
        let lease = self
            .ledger
            .create_snapshot_lease_for_at_catalog(
                now,
                remaining_ttl(now, expiry)?,
                catalog_identity,
            )
            .map_err(map_ledger_failure)?;
        let trace_lease = match trace_ledger {
            Some(trace_ledger) => {
                let (reauthorized_tenant, trace_catalog_identity, _) =
                    match self.current_query_catalog(query.context) {
                        Ok(current) => current,
                        Err(failure) => {
                            return Err(self.fail_after_source_lease(lease.identity(), failure));
                        },
                    };
                if reauthorized_tenant != tenant {
                    let failure = QueryFailure::new(QueryFailureCode::AuthorizationChanged);
                    return Err(self.fail_after_source_lease(lease.identity(), failure));
                }
                match trace_ledger.create_snapshot_lease_for_at_catalog(
                    now,
                    remaining_ttl(now, expiry)?,
                    trace_catalog_identity,
                ) {
                    Ok(lease) => Some(lease),
                    Err(failure) => {
                        let primary = map_ledger_failure(failure);
                        return Err(self.fail_after_source_lease(lease.identity(), primary));
                    },
                }
            },
            None => None,
        };
        let (mut state, reservation) =
            initial_state(query, lease.snapshot(), tenant, expiry, lease.identity());
        if let Some(trace_lease) = trace_lease.as_ref() {
            state.trace_catalog_identity =
                Some(trace_lease.snapshot().catalog_identity().to_bytes());
            state.trace_catalog_generation = Some(trace_lease.snapshot().catalog_generation());
            state.trace_frontier = Some(trace_lease.snapshot().frontier().value());
            state.trace_lease_identity = Some(trace_lease.identity().to_bytes());
        }
        let limit = state.plan.limit();
        let resources = match trace_lease.as_ref() {
            Some(trace_lease) => {
                ExecutionResources::new(reservation, lease.identity(), lease.usage())
                    .with_target_lease(trace_lease.identity(), trace_lease.usage())
            },
            None => ExecutionResources::new(reservation, lease.identity(), lease.usage()),
        };
        self.run_page(
            state,
            lease.snapshot(),
            super::page::PageInput {
                trace_snapshot: trace_lease.as_ref().map(|lease| lease.snapshot()),
                trace_lease: trace_lease.as_ref().map(|lease| lease.identity()),
                batch_limit: limit,
                pagination: false,
                schema,
            },
            resources,
        )
    }

    pub fn execute_page(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        if query.plan.is_log_to_trace_correlation() && self.trace_ledger.is_none() {
            return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        }
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
        let trace_ledger = if query.plan.is_log_to_trace_correlation() {
            let trace_ledger = self
                .trace_ledger
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            if trace_ledger.scope().tenant_id() != tenant {
                return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
            }
            if trace_ledger.scope().signal_kind() != positron_domain::routing::SignalKind::Traces {
                return Err(QueryFailure::new(QueryFailureCode::MalformedPersistentData));
            }
            Some(trace_ledger)
        } else {
            None
        };
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
        let trace_lease = match trace_ledger {
            Some(trace_ledger) => {
                let (reauthorized_tenant, trace_catalog_identity, _) =
                    match self.current_query_catalog(query.context) {
                        Ok(current) => current,
                        Err(failure) => {
                            return Err(self.fail_after_source_lease(lease.identity(), failure));
                        },
                    };
                if reauthorized_tenant != tenant {
                    let failure = QueryFailure::new(QueryFailureCode::AuthorizationChanged);
                    return Err(self.fail_after_source_lease(lease.identity(), failure));
                }
                match trace_ledger.create_snapshot_lease_for_at_catalog(
                    now_seconds,
                    remaining_ttl(now_seconds, expiry)?,
                    trace_catalog_identity,
                ) {
                    Ok(lease) => Some(lease),
                    Err(failure) => {
                        let primary = map_ledger_failure(failure);
                        return Err(self.fail_after_source_lease(lease.identity(), primary));
                    },
                }
            },
            None => None,
        };
        let (mut state, reservation) =
            initial_state(query, lease.snapshot(), tenant, expiry, lease.identity());
        if let Some(trace_lease) = trace_lease.as_ref() {
            state.trace_catalog_identity =
                Some(trace_lease.snapshot().catalog_identity().to_bytes());
            state.trace_catalog_generation = Some(trace_lease.snapshot().catalog_generation());
            state.trace_frontier = Some(trace_lease.snapshot().frontier().value());
            state.trace_lease_identity = Some(trace_lease.identity().to_bytes());
        }
        let resources = match trace_lease.as_ref() {
            Some(trace_lease) => {
                ExecutionResources::new(reservation, lease.identity(), lease.usage())
                    .with_target_lease(trace_lease.identity(), trace_lease.usage())
            },
            None => ExecutionResources::new(reservation, lease.identity(), lease.usage()),
        };
        self.run_page(
            state,
            lease.snapshot(),
            super::page::PageInput {
                trace_snapshot: trace_lease.as_ref().map(|lease| lease.snapshot()),
                trace_lease: trace_lease.as_ref().map(|lease| lease.identity()),
                batch_limit: self.batch_limit,
                pagination: true,
                schema: None,
            },
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
                return Err(resources.fail_during_resume_planning(
                    self.ledger,
                    self.trace_ledger,
                    &state,
                    failure,
                ));
            },
        };
        let source_reservation = match planning_memory.reserve(source_length) {
            Ok(reservation) => reservation,
            Err(failure) => {
                return Err(resources.fail_during_resume_planning(
                    self.ledger,
                    self.trace_ledger,
                    &state,
                    failure,
                ));
            },
        };
        let decoded = match cursor::decode(&self.ledger.control_tokens(), cursor) {
            Ok(decoded) => decoded,
            Err(failure) => {
                return Err(resources.fail_during_resume_planning(
                    self.ledger,
                    self.trace_ledger,
                    &state,
                    failure,
                ));
            },
        };
        state.source = decoded.source;
        state.language = decoded.language;
        if let Err(failure) = self.reconstruct_plan(&mut state, &planning_memory) {
            return Err(resources.fail_during_resume_planning(
                self.ledger,
                self.trace_ledger,
                &state,
                failure,
            ));
        }
        drop(source_reservation);
        if lease.snapshot().catalog_identity().to_bytes() != state.catalog_identity
            || lease.snapshot().catalog_generation() != state.catalog_generation
            || lease.snapshot().frontier().value() != state.frontier
        {
            return Err(resources.fail_before_stream(
                self.ledger,
                self.trace_ledger,
                &state,
                QueryFailure::new(QueryFailureCode::InvalidCursor),
            ));
        }
        let (trace_snapshot, trace_lease_identity, resources) = if state
            .plan
            .is_log_to_trace_correlation()
        {
            let (
                Some(trace_catalog_identity),
                Some(trace_catalog_generation),
                Some(trace_frontier),
                Some(trace_lease_identity),
            ) = (
                state.trace_catalog_identity,
                state.trace_catalog_generation,
                state.trace_frontier,
                state.trace_lease_identity,
            )
            else {
                return Err(resources.fail_before_stream(
                    self.ledger,
                    self.trace_ledger,
                    &state,
                    QueryFailure::new(QueryFailureCode::InvalidCursor),
                ));
            };
            let trace_ledger = match self.trace_ledger {
                Some(ledger)
                    if ledger.scope().tenant_id() == tenant
                        && ledger.scope().signal_kind()
                            == positron_domain::routing::SignalKind::Traces =>
                {
                    ledger
                },
                Some(_) => {
                    return Err(resources.fail_before_stream(
                        self.ledger,
                        self.trace_ledger,
                        &state,
                        QueryFailure::new(QueryFailureCode::Unauthorized),
                    ));
                },
                None => {
                    return Err(resources.fail_before_stream(
                        self.ledger,
                        None,
                        &state,
                        QueryFailure::new(QueryFailureCode::StoreUnavailable),
                    ));
                },
            };
            let (_, target_catalog_identity, target_catalog_generation) =
                match self.current_query_catalog(context) {
                    Ok(current) => current,
                    Err(failure) => {
                        return Err(resources.fail_before_stream(
                            self.ledger,
                            self.trace_ledger,
                            &state,
                            failure,
                        ));
                    },
                };
            let target_lease_id = match SnapshotLeaseId::new(trace_lease_identity) {
                Ok(identity) => identity,
                Err(_) => {
                    return Err(resources.fail_before_stream(
                        self.ledger,
                        self.trace_ledger,
                        &state,
                        QueryFailure::new(QueryFailureCode::InvalidCursor),
                    ));
                },
            };
            let mut target_lease = match trace_ledger.resume_snapshot_lease_with_marker_at_catalog(
                target_lease_id,
                now_seconds,
                state.sequence,
                state.prior_digest,
                target_catalog_identity,
                target_catalog_generation,
            ) {
                Ok(lease) => lease,
                Err(failure) => {
                    return Err(resources.fail_before_stream(
                        self.ledger,
                        self.trace_ledger,
                        &state,
                        map_ledger_failure(failure),
                    ));
                },
            };
            if target_lease.snapshot().catalog_identity().to_bytes() != trace_catalog_identity
                || target_lease.snapshot().catalog_generation() != trace_catalog_generation
                || target_lease.snapshot().frontier().value() != trace_frontier
            {
                let primary = match trace_ledger.release_snapshot_lease(target_lease.identity()) {
                    Ok(()) => QueryFailure::new(QueryFailureCode::InvalidCursor),
                    Err(failure) => crate::failure::stronger_failure(
                        QueryFailure::new(QueryFailureCode::InvalidCursor),
                        map_ledger_failure(failure),
                    ),
                };
                return Err(resources.fail_before_stream(
                    self.ledger,
                    self.trace_ledger,
                    &state,
                    primary,
                ));
            }
            let target_attempt = match target_lease.take_attempt() {
                Some(attempt) => attempt,
                None => {
                    let primary = match trace_ledger.release_snapshot_lease(target_lease.identity())
                    {
                        Ok(()) => QueryFailure::new(QueryFailureCode::Internal),
                        Err(failure) => crate::failure::stronger_failure(
                            QueryFailure::new(QueryFailureCode::Internal),
                            map_ledger_failure(failure),
                        ),
                    };
                    return Err(resources.fail_before_stream(
                        self.ledger,
                        self.trace_ledger,
                        &state,
                        primary,
                    ));
                },
            };
            let identity = target_lease.identity();
            let resources =
                resources.with_target_attempt(identity, target_lease.usage(), target_attempt);
            (Some(target_lease), Some(identity), resources)
        } else {
            if state.trace_catalog_identity.is_some()
                || state.trace_catalog_generation.is_some()
                || state.trace_frontier.is_some()
                || state.trace_lease_identity.is_some()
            {
                return Err(resources.fail_before_stream(
                    self.ledger,
                    self.trace_ledger,
                    &state,
                    QueryFailure::new(QueryFailureCode::InvalidCursor),
                ));
            }
            (None, None, resources)
        };
        let mut state = state;
        state.resume_count = lease.resume_count();
        state.repeated_batch_count = lease.repeated_batch_count();
        state.last_observed_at = now_seconds;
        self.run_page(
            state,
            lease.snapshot(),
            super::page::PageInput {
                trace_snapshot: trace_snapshot.as_ref().map(|lease| lease.snapshot()),
                trace_lease: trace_lease_identity,
                batch_limit: self.batch_limit,
                pagination: true,
                schema: None,
            },
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
