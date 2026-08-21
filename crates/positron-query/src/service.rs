use positron_domain::identity::Scope;
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ActiveSegmentLedger, ResourceAmounts, ResourceGovernor, WorkClaim, WorkKind,
};
use std::sync::Arc;

use crate::{
    LogicalPlan, PlannedQuery, QueryBudget, QueryFailure, QueryFailureCode, TemporalAxis,
    TemporalRange,
};
use crate::plan::{AggregateSpec, FilterPredicate, ProjectionColumn};

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
        parser: fn(&str) -> Result<LogicalPlan, QueryFailure>,
    ) -> Result<PlannedQuery<'kernel>, QueryFailure> {
        let tenant = context
            .tenant_attribution()
            .filter(|attribution| attribution.scope() == Scope::Query)
            .map(|attribution| attribution.tenant_id())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Unauthorized))?;
        let started_at = self.now()?;
        let reservation = self.reserve_query(tenant, budget)?;
        let cpu_work_units = self.work_units(crate::QueryWorkStage::Parse)?;
        let plan = parser(source)?;
        let last_observed_at = self.now()?;
        if last_observed_at < started_at {
            return Err(QueryFailure::new(QueryFailureCode::Internal));
        }
        if last_observed_at.saturating_sub(started_at) >= budget.wall_seconds()
            || cpu_work_units > budget.cpu_work_units()
        {
            return Err(QueryFailure::new(QueryFailureCode::BudgetExhausted));
        }
        if plan.limit() == 0
            || plan.limit() > 1_024
            || u64::from(plan.limit()) > budget.output_rows()
            || plan
                .temporal_range()
                .duration()
                .is_none_or(|duration| duration > budget.maximum_time_range_nanoseconds())
        {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        Ok(PlannedQuery {
            context,
            plan,
            budget,
            _reservation: reservation,
            started_at,
            last_observed_at,
            cpu_work_units,
        })
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

pub(crate) fn parse_pipeline(source: &str) -> Result<LogicalPlan, QueryFailure> {
    if source.starts_with("pipeline:v1 ") {
        return parse_versioned_pipeline(source);
    }
    let tokens = source.split_ascii_whitespace().collect::<Vec<_>>();
    match tokens.as_slice() {
        [
            "pipeline:v1",
            "logs",
            "|",
            "range",
            axis,
            start,
            end,
            "|",
            "filter",
            "body",
            "==",
            literal,
            "|",
            "limit",
            limit,
        ] => plan(axis, start, end, limit).and_then(|plan| {
            parse_body_literal(literal)
                .map(|literal| plan.with_filter(FilterPredicate::BodyEquals(literal)))
        }),
        [
            "pipeline:v1",
            "logs",
            "|",
            "range",
            axis,
            start,
            end,
            "|",
            "project",
            first,
            "|",
            "limit",
            limit,
        ] => plan(axis, start, end, limit).and_then(|plan| {
            parse_projection(&[first]).map(|projection| plan.with_projection(projection))
        }),
        [
            "pipeline:v1",
            "logs",
            "|",
            "range",
            axis,
            start,
            end,
            "|",
            "project",
            first,
            second,
            "|",
            "limit",
            limit,
        ] => plan(axis, start, end, limit).and_then(|plan| {
            parse_projection(&[first, second]).map(|projection| plan.with_projection(projection))
        }),
        [
            "pipeline:v1",
            "logs",
            "|",
            "range",
            axis,
            start,
            end,
            "|",
            "project",
            first,
            second,
            third,
            "|",
            "limit",
            limit,
        ] => plan(axis, start, end, limit).and_then(|plan| {
            parse_projection(&[first, second, third]).map(|projection| plan.with_projection(projection))
        }),
        ["pipeline:v1", "logs", "|", "range", axis, start, end, "|", "limit", limit] => {
            plan(axis, start, end, limit)
        },
        ["logs", "|", "range", axis, start, end, "|", "limit", limit] => {
            plan(axis, start, end, limit)
        },
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}

fn parse_versioned_pipeline(source: &str) -> Result<LogicalPlan, QueryFailure> {
    if source.len() > 4_096 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let mut stages = source.split('|').map(str::trim);
    if stages.next() != Some("pipeline:v1 logs") {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let mut range = None;
    let mut filter = None;
    let mut projection = None;
    let mut aggregate = None;
    let mut limit = None;
    for stage in stages {
        if let Some(arguments) = stage.strip_prefix("range ") {
            let tokens = arguments.split_ascii_whitespace().collect::<Vec<_>>();
            if tokens.len() != 3 || range.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            range = Some((tokens[0], tokens[1], tokens[2]));
        } else if let Some(literal) = stage.strip_prefix("filter body == ") {
            if filter.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(parse_body_literal(literal)?);
        } else if let Some(literal) = stage.strip_prefix("search body == ") {
            if filter.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(parse_body_literal(literal)?);
        } else if let Some(columns) = stage.strip_prefix("project ") {
            if projection.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            projection = Some(parse_projection(
                &columns.split_ascii_whitespace().collect::<Vec<_>>(),
            )?);
        } else if stage == "aggregate count" {
            if aggregate.replace(AggregateSpec::Count).is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
        } else if let Some(value) = stage.strip_prefix("limit ") {
            if limit.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            limit = Some(value);
        } else {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
    }
    let (axis, start, end) = range.ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    let mut plan = plan(
        axis,
        start,
        end,
        limit.ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?,
    )?;
    if let Some(filter) = filter {
        plan = plan.with_filter(FilterPredicate::BodyEquals(filter));
    }
    if let Some(projection) = projection {
        plan = plan.with_projection(projection);
    }
    if let Some(aggregate) = aggregate {
        plan = plan.with_aggregate(aggregate);
    }
    Ok(plan)
}

pub(crate) fn parse_sql(source: &str) -> Result<LogicalPlan, QueryFailure> {
    let normalized = source.trim().to_ascii_lowercase();
    let tokens = normalized.split_ascii_whitespace().collect::<Vec<_>>();
    match tokens.as_slice() {
        [
            "select",
            "body",
            "from",
            "logs",
            "where",
            axis,
            ">=",
            start,
            "and",
            upper_axis,
            "<",
            end,
            "order",
            "by",
            ordered_axis,
            "commit_position",
            "limit",
            limit,
        ] if *upper_axis == *axis && ordered_axis.strip_suffix(',') == Some(axis) => {
            plan(axis, start, end, limit)
        },
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}

fn plan(axis: &str, start: &str, end: &str, limit: &str) -> Result<LogicalPlan, QueryFailure> {
    let axis = match axis {
        "query_time" => TemporalAxis::QueryTime,
        "event_time" => TemporalAxis::EventTime,
        _ => return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    };
    let start = parse_timestamp(start)?;
    let end = parse_timestamp(end)?;
    let range = TemporalRange::new(start, end)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
    Ok(LogicalPlan::logs(axis, range, parse_limit(limit)?))
}

fn parse_timestamp(source: &str) -> Result<i64, QueryFailure> {
    if source.starts_with('+')
        || (source.starts_with('0') && source.len() > 1)
        || (source.starts_with("-0") && source.len() > 2)
    {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    source
        .parse()
        .map_err(|_| QueryFailure::new(QueryFailureCode::UnsupportedQuery))
}

fn parse_limit(source: &str) -> Result<u16, QueryFailure> {
    if source.starts_with('0') && source.len() > 1 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    source
        .parse()
        .map_err(|_| QueryFailure::new(QueryFailureCode::UnsupportedQuery))
}

fn parse_body_literal(source: &str) -> Result<String, QueryFailure> {
    let Some(inner) = source
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    };
    if inner.is_empty() || inner.len() > 65_536 || inner.contains('"') {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    Ok(inner.to_owned())
}

fn parse_projection(parts: &[&str]) -> Result<Vec<ProjectionColumn>, QueryFailure> {
    if parts.is_empty() || parts.len() > 3 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let mut projection = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let is_last = index + 1 == parts.len();
        let column = if is_last {
            *part
        } else {
            part.strip_suffix(',').ok_or_else(|| {
                QueryFailure::new(QueryFailureCode::UnsupportedQuery)
            })?
        };
        let column = match column {
            "body" => ProjectionColumn::Body,
            "query_time" => ProjectionColumn::QueryTime,
            "commit_position" => ProjectionColumn::CommitPosition,
            _ => return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
        };
        if projection.contains(&column) {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        projection.push(column);
    }
    Ok(projection)
}
