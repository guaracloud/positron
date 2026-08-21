use positron_governance::AuthorizedContext;
use positron_kernel::SnapshotLeaseId;

use crate::cursor;
use crate::execution_state::{initial_state, query_tenant, validate_authorization};
use crate::execution_support::map_ledger_failure;
use crate::{PlannedQuery, QueryCursor, QueryFailure, QueryFailureCode, QueryService, QueryStream};

use super::resources::ExecutionResources;

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
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
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
        let lease = self
            .ledger
            .create_snapshot_lease(now, expiry)
            .map_err(map_ledger_failure)?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, lease.snapshot(), tenant, expiry, lease.identity());
        let limit = query.plan.limit();
        let resources = ExecutionResources::new(query._reservation, lease.identity());
        self.run_page(state, lease.snapshot(), limit, false, schema, resources)
    }

    pub fn execute_page(
        &self,
        query: PlannedQuery<'kernel>,
    ) -> Result<QueryStream<'ledger>, QueryFailure> {
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        if self.batch_limit == 0 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        if query.plan.has_advanced_operators() {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        let now_seconds = self.observe_planned(&query)?;
        let expiry = query
            .started_at
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        let lease = self
            .ledger
            .create_snapshot_lease(now_seconds, expiry)
            .map_err(map_ledger_failure)?;
        let tenant = query_tenant(query.context)?;
        let state = initial_state(&query, lease.snapshot(), tenant, expiry, lease.identity());
        let resources = ExecutionResources::new(query._reservation, lease.identity());
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
        let tenant = query_tenant(context)?;
        let state = cursor::decode(&self.ledger.control_tokens(), cursor)?;
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
        if now_seconds >= state.expiry {
            return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
        }
        let reservation = self.reserve_query(tenant, state.budget)?;
        let lease_id = SnapshotLeaseId::new(state.lease_identity)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let lease = self
            .ledger
            .resume_snapshot_lease(lease_id, now_seconds)
            .map_err(map_ledger_failure)?;
        let resources = ExecutionResources::new(reservation, lease.identity());
        if lease.snapshot().catalog_identity().to_bytes() != state.catalog_identity
            || lease.snapshot().catalog_generation() != state.catalog_generation
            || lease.snapshot().frontier().value() != state.frontier
            || lease.expiry() != state.expiry
        {
            return Err(resources.fail_before_stream(
                self.ledger,
                QueryFailure::new(QueryFailureCode::InvalidCursor),
            ));
        }
        let mut state = state;
        state.last_observed_at = now_seconds;
        state.elapsed_wall_seconds = now_seconds.saturating_sub(state.started_at);
        self.run_page(
            state,
            lease.snapshot(),
            self.batch_limit,
            true,
            None,
            resources,
        )
    }

    fn observe_planned(&self, query: &PlannedQuery<'_>) -> Result<u64, QueryFailure> {
        let now = self.now()?;
        if now < query.last_observed_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        Ok(now)
    }
}
