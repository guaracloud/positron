use positron_domain::identity::Scope;
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ActiveSegmentLedger, ResourceAmounts, ResourceGovernor, WorkClaim, WorkKind,
};

use crate::{LogicalPlan, PlannedQuery, QueryBudget, QueryFailure, QueryFailureCode};

pub struct CursorKey {
    pub(crate) epoch: u32,
    pub(crate) key: [u8; 32],
}

impl CursorKey {
    pub fn new(epoch: u32, key: [u8; 32]) -> Result<Self, QueryFailure> {
        if epoch == 0 || key.iter().all(|byte| *byte == 0) {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        Ok(Self { epoch, key })
    }
}

pub struct QueryService<'kernel, 'catalog, 'ledger> {
    pub(crate) governor: ResourceGovernor<'kernel>,
    pub(crate) ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    pub(crate) cursor_key: CursorKey,
    pub(crate) batch_limit: u16,
}

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub const fn new(
        governor: ResourceGovernor<'kernel>,
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
        cursor_key: CursorKey,
        batch_limit: u16,
    ) -> Self {
        Self {
            governor,
            ledger,
            cursor_key,
            batch_limit,
        }
    }

    pub fn plan_pipeline(
        &self,
        context: AuthorizedContext,
        source: &str,
        budget: QueryBudget,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        self.plan(context, source, budget, parse_pipeline)
    }

    pub fn plan_sql(
        &self,
        context: AuthorizedContext,
        source: &str,
        budget: QueryBudget,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        self.plan(context, source, budget, parse_sql)
    }

    fn plan(
        &self,
        context: AuthorizedContext,
        source: &str,
        budget: QueryBudget,
        parser: fn(&str) -> Result<u16, QueryFailure>,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        let tenant = context
            .tenant_attribution()
            .filter(|attribution| attribution.scope() == Scope::Query)
            .map(|attribution| attribution.tenant_id())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        let reservation = self.reserve_query(tenant, budget)?;
        let limit = parser(source)?;
        if limit == 0 || limit > 1_024 || u64::from(limit) > budget.output_rows() {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        Ok(PlannedQuery {
            context,
            plan: LogicalPlan::logs(limit),
            budget,
            _reservation: reservation,
        })
    }

    pub(crate) fn reserve_query(
        &self,
        tenant: positron_domain::identity::TenantId,
        budget: QueryBudget,
    ) -> Result<positron_kernel::ResourceReservation<'kernel>, QueryFailure> {
        let amounts = ResourceAmounts::new([budget.memory_bytes(), 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
        let claim = WorkClaim::tenant(tenant, WorkKind::InteractiveQueryTail, amounts)
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
        self.governor
            .reserve(claim)
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused))
    }
}

pub(crate) fn parse_pipeline(source: &str) -> Result<u16, QueryFailure> {
    let tokens = source.split_ascii_whitespace().collect::<Vec<_>>();
    match tokens.as_slice() {
        ["logs", "|", "limit", limit] => parse_limit(limit),
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}

pub(crate) fn parse_sql(source: &str) -> Result<u16, QueryFailure> {
    let normalized = source.trim().to_ascii_lowercase();
    let ordered = "select body from logs order by query_time, commit_position limit ";
    let minimal = "select body from logs limit ";
    normalized
        .strip_prefix(ordered)
        .or_else(|| normalized.strip_prefix(minimal))
        .filter(|limit| !limit.is_empty() && !limit.contains(char::is_whitespace))
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))
        .and_then(parse_limit)
}

fn parse_limit(source: &str) -> Result<u16, QueryFailure> {
    if source.starts_with('0') && source.len() > 1 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    source
        .parse()
        .map_err(|_| QueryFailure::new(QueryFailureCode::UnsupportedQuery))
}
