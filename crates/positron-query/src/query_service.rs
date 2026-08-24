use std::sync::Arc;

use positron_domain::identity::Scope;
use positron_governance::{AuthorizedContext, Identity};
use positron_kernel::{
    ActiveSegmentLedger, CatalogGenerationId, ResourceAmounts, ResourceGovernor, WorkClaim,
    WorkKind,
};

use crate::{
    LogicalPlan, PlannedQuery, QueryBudget, QueryBudgetDimension, QueryFailure, QueryFailureCode,
};

const MAX_QUERY_SOURCE_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryLanguage {
    Pipeline,
    Sql,
}

pub struct QueryService<'kernel, 'catalog, 'ledger> {
    pub(crate) governor: ResourceGovernor<'kernel>,
    pub(crate) ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    pub(crate) batch_limit: u16,
    pub(crate) clock: Arc<dyn crate::QueryClock>,
    pub(crate) work_meter: Arc<dyn crate::QueryWorkMeter>,
}

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn new(
        governor: ResourceGovernor<'kernel>,
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
        batch_limit: u16,
    ) -> Self {
        Self::with_runtime(
            governor,
            ledger,
            batch_limit,
            Arc::new(crate::runtime::SystemQueryClock),
            Arc::new(crate::runtime::FixedQueryWorkMeter),
        )
    }

    pub fn with_clock(
        governor: ResourceGovernor<'kernel>,
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
        batch_limit: u16,
        clock: Arc<dyn crate::QueryClock>,
    ) -> Self {
        Self::with_runtime(
            governor,
            ledger,
            batch_limit,
            clock,
            Arc::new(crate::runtime::FixedQueryWorkMeter),
        )
    }

    pub fn with_runtime(
        governor: ResourceGovernor<'kernel>,
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
        batch_limit: u16,
        clock: Arc<dyn crate::QueryClock>,
        work_meter: Arc<dyn crate::QueryWorkMeter>,
    ) -> Self {
        Self {
            governor,
            ledger,
            batch_limit,
            clock,
            work_meter,
        }
    }

    pub fn plan_pipeline(
        &self,
        context: AuthorizedContext,
        source: &str,
        budget: QueryBudget,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        self.plan(context, source, budget, QueryLanguage::Pipeline)
    }

    pub fn plan_sql(
        &self,
        context: AuthorizedContext,
        source: &str,
        budget: QueryBudget,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        self.plan(context, source, budget, QueryLanguage::Sql)
    }

    fn plan(
        &self,
        context: AuthorizedContext,
        source: &str,
        budget: QueryBudget,
        language: QueryLanguage,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        let tenant = context
            .tenant_attribution()
            .filter(|attribution| attribution.scope() == Scope::Query)
            .map(|attribution| attribution.tenant_id())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        self.validate_current_query_context(context)?;
        if source.len() > MAX_QUERY_SOURCE_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        let started_at = self.now()?;
        let reservation = self.reserve_query(tenant, budget)?;
        let planning_memory = crate::planning_memory::PlanningMemory::new(budget.memory_bytes());
        let source_memory = planning_memory.reserve(
            u64::try_from(source.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?,
        )?;
        let parse_work_units = self.work_units(crate::QueryWorkStage::Parse)?;
        let (plan, planning_memory_reservation, compile_work_units) =
            self.compile_plan(source, language, &planning_memory, budget)?;
        let mut source_bytes = Vec::new();
        source_bytes
            .try_reserve_exact(source.len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        source_bytes.extend_from_slice(source.as_bytes());
        let cpu_work_units = if compile_work_units == 0 {
            parse_work_units
        } else {
            let compile_unit_cost = self.work_units(crate::QueryWorkStage::Parse)?;
            let compile_work = compile_unit_cost
                .checked_mul(compile_work_units)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            parse_work_units
                .checked_add(compile_work)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
        };
        let last_observed_at = self.now()?;
        if last_observed_at < started_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        if last_observed_at.saturating_sub(started_at) >= budget.wall_seconds() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::WallSeconds,
            ));
        }
        if cpu_work_units > budget.cpu_work_units() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::CpuWorkUnits,
            ));
        }
        let plan_digest = plan.canonical_digest(&self.ledger.control_tokens())?;
        drop(source_memory);
        Ok(PlannedQuery {
            context,
            plan: Arc::new(plan),
            source: Arc::from(source_bytes.into_boxed_slice()),
            language,
            budget,
            plan_digest,
            _reservation: reservation,
            _planning_memory: planning_memory_reservation,
            started_at,
            last_observed_at,
            cpu_work_units,
            cancellation: crate::QueryCancellation::new(),
        })
    }

    pub(crate) fn compile_plan(
        &self,
        source: &str,
        language: QueryLanguage,
        memory: &crate::planning_memory::PlanningMemory,
        budget: QueryBudget,
    ) -> Result<
        (
            LogicalPlan,
            crate::planning_memory::PlanningReservation,
            u64,
        ),
        QueryFailure,
    > {
        let mut plan = match language {
            QueryLanguage::Pipeline => crate::service::parse_pipeline(source, memory)?,
            QueryLanguage::Sql => crate::service::parse_sql(source, memory)?,
        };
        let parser_retained = memory.take_retained();
        let compile_work_units = plan.search_compile_work_units();
        plan.compile_search()?;
        self.validate_plan_bounds(&plan, budget)?;
        let retained_plan_bytes = plan
            .retained_memory_bytes()?
            .checked_sub(parser_retained.bytes())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let plan_reservation = memory.reserve(retained_plan_bytes)?;
        drop(parser_retained);
        Ok((plan, plan_reservation, compile_work_units))
    }

    fn validate_plan_bounds(
        &self,
        plan: &LogicalPlan,
        budget: QueryBudget,
    ) -> Result<(), QueryFailure> {
        if plan.limit() == 0 || plan.limit() > 1_024 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        if u64::from(plan.limit()) > budget.output_rows() {
            return Err(QueryFailure::for_budget(
                QueryFailureCode::InvalidBudget,
                QueryBudgetDimension::OutputRows,
            ));
        }
        if plan
            .temporal_range()
            .duration()
            .is_none_or(|duration| duration > budget.maximum_time_range_nanoseconds())
        {
            return Err(QueryFailure::for_budget(
                QueryFailureCode::InvalidBudget,
                QueryBudgetDimension::MaximumTimeRangeNanoseconds,
            ));
        }
        let retained = plan.retained_memory_bytes()?;
        if retained
            .checked_add(plan.search_memory_bytes())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
            > budget.memory_bytes()
        {
            return Err(QueryFailure::for_budget(
                QueryFailureCode::InvalidBudget,
                QueryBudgetDimension::MemoryBytes,
            ));
        }
        Ok(())
    }

    pub(crate) fn reserve_query(
        &self,
        tenant: positron_domain::identity::TenantId,
        budget: QueryBudget,
    ) -> Result<positron_kernel::ResourceReservation<'kernel>, QueryFailure> {
        let amounts = ResourceAmounts::new([
            budget.memory_bytes(),
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            budget.cpu_work_units(),
            0,
            0,
        ]);
        let claim = WorkClaim::tenant(tenant, WorkKind::InteractiveQueryTail, amounts)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        self.governor
            .reserve(claim)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused))
    }

    pub(crate) fn validate_current_query_context(
        &self,
        context: AuthorizedContext,
    ) -> Result<positron_domain::identity::TenantId, QueryFailure> {
        self.current_query_catalog(context)
            .map(|(tenant, _)| tenant)
    }

    pub(crate) fn current_query_catalog(
        &self,
        context: AuthorizedContext,
    ) -> Result<(positron_domain::identity::TenantId, CatalogGenerationId), QueryFailure> {
        let tenant = crate::execution_state::query_tenant(context)?;
        let snapshot = self
            .ledger
            .current_catalog_snapshot()
            .map_err(crate::execution_support::map_ledger_failure)?;
        let identity = Identity::open(&snapshot)
            .map_err(|_| QueryFailure::new(QueryFailureCode::MalformedPersistentData))?;
        identity
            .revalidate_query_context(context)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        Ok((tenant, snapshot.identity()))
    }

    pub(crate) fn now(&self) -> Result<u64, QueryFailure> {
        self.clock
            .now_seconds()
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
    }

    pub(crate) fn work_units(&self, stage: crate::QueryWorkStage) -> Result<u64, QueryFailure> {
        self.work_meter
            .units(stage)
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
    }
}
