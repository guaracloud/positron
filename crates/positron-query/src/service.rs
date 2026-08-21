use positron_domain::identity::Scope;
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ActiveSegmentLedger, ResourceAmounts, ResourceGovernor, WorkClaim, WorkKind,
};
use std::sync::Arc;

use crate::plan::{AggregateSpec, FilterPredicate, OrderDirection, OrderSpec, ProjectionColumn};
use crate::{
    LogicalPlan, PlannedQuery, QueryBudget, QueryFailure, QueryFailureCode, TemporalAxis,
    TemporalRange,
};

const MAX_QUERY_SOURCE_BYTES: usize = 4_096;

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
        if source.len() > MAX_QUERY_SOURCE_BYTES {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
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
            cancellation: crate::QueryCancellation::new(),
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
    let stages = pipeline_stages(source)?;
    if stages.first() == Some(&"pipeline:v1 logs") {
        return parse_versioned_pipeline(&stages);
    }
    match stages.as_slice() {
        ["logs", range, limit] => {
            let range = range.split_ascii_whitespace().collect::<Vec<_>>();
            let limit = limit.split_ascii_whitespace().collect::<Vec<_>>();
            match (range.as_slice(), limit.as_slice()) {
                (["range", axis, start, end], ["limit", limit]) => plan(axis, start, end, limit),
                _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
            }
        },
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}

fn pipeline_stages(source: &str) -> Result<Vec<&str>, QueryFailure> {
    let capacity = source
        .bytes()
        .filter(|byte| *byte == b'|')
        .count()
        .checked_add(1)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(capacity)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in source.char_indices() {
        if escaped {
            if !matches!(character, '"' | '\\' | '|') {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            escaped = false;
        } else {
            match character {
                '\\' if quoted => escaped = true,
                '\\' => return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
                '"' => quoted = !quoted,
                '|' if !quoted => {
                    let stage = source
                        .get(start..index)
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
                    stages.push(stage.trim());
                    start = index
                        .checked_add(character.len_utf8())
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
                },
                _ => {},
            }
        }
    }
    if quoted || escaped {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let stage = source
        .get(start..)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    stages.push(stage.trim());
    Ok(stages)
}

fn parse_versioned_pipeline(stages: &[&str]) -> Result<LogicalPlan, QueryFailure> {
    let Some((&header, remaining_stages)) = stages.split_first() else {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    };
    if header != "pipeline:v1 logs" {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let mut range = None;
    let mut filter = None;
    let mut projection = None;
    let mut aggregate = None;
    let mut ordering = None;
    let mut limit = None;
    let mut stage_order = 0_u8;
    for &stage in remaining_stages {
        if limit.is_some() || (!stage.starts_with("range ") && range.is_none()) {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        if let Some(arguments) = stage.strip_prefix("range ") {
            let tokens = arguments.split_ascii_whitespace().collect::<Vec<_>>();
            let &[axis, start, end] = tokens.as_slice() else {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            };
            if range.is_some() || stage_order != 0 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            range = Some((axis, start, end));
            stage_order = 1;
        } else if let Some(literal) = stage.strip_prefix("filter body == ") {
            if filter.is_some() || stage_order > 1 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(parse_body_literal(literal)?);
            stage_order = 2;
        } else if let Some(literal) = stage.strip_prefix("search body == ") {
            if filter.is_some() || stage_order > 1 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(parse_body_literal(literal)?);
            stage_order = 2;
        } else if let Some(columns) = stage.strip_prefix("project ") {
            if projection.is_some() || aggregate.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            projection = Some(parse_projection(
                &columns.split_ascii_whitespace().collect::<Vec<_>>(),
            )?);
            stage_order = 3;
        } else if stage == "aggregate count" || stage.starts_with("aggregate count by ") {
            if projection.is_some() || aggregate.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            aggregate = Some(parse_aggregate(stage)?);
            stage_order = 3;
        } else if let Some(specification) = stage.strip_prefix("order by ") {
            if ordering.is_some() || aggregate.is_some() || stage_order > 3 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            ordering = Some(specification.to_owned());
            stage_order = 4;
        } else if let Some(value) = stage.strip_prefix("limit ") {
            if limit.is_some() {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            limit = Some(value);
        } else {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
    }
    let (axis, start, end) =
        range.ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
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
    if let Some(ordering) = ordering {
        let parsed = parse_ordering(plan.temporal_axis(), &ordering)?;
        plan = plan.with_ordering(parsed);
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
        "ingest_time" => TemporalAxis::IngestTime,
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

fn parse_body_literal(
    source: &str,
) -> Result<positron_domain::value::ValidatedAttributeValue, QueryFailure> {
    let Some(inner) = source
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    };
    if inner.len() > 65_536 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let mut decoded = String::new();
    decoded
        .try_reserve_exact(inner.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters
                .next()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
            if !matches!(escaped, '"' | '\\' | '|') {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            decoded.push(escaped);
        } else if character == '"' {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        } else {
            decoded.push(character);
        }
    }
    positron_domain::value::CandidateAttributeValue::string(decoded)
        .validate_log_body(positron_domain::value::ValueLimitProfile::release_1_system_maximum())
        .map_err(|failure| {
            if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable
            {
                QueryFailure::new(QueryFailureCode::ResourceExhausted)
            } else {
                QueryFailure::new(QueryFailureCode::UnsupportedQuery)
            }
        })
}

fn parse_projection(parts: &[&str]) -> Result<Vec<ProjectionColumn>, QueryFailure> {
    if parts.is_empty() || parts.len() > 5 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let mut projection = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let is_last = index + 1 == parts.len();
        let column = if is_last {
            *part
        } else {
            part.strip_suffix(',')
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?
        };
        let column = match column {
            "body" => ProjectionColumn::Body,
            "query_time" => ProjectionColumn::QueryTime,
            "event_time" => ProjectionColumn::EventTime,
            "ingest_time" => ProjectionColumn::IngestTime,
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

fn parse_aggregate(stage: &str) -> Result<AggregateSpec, QueryFailure> {
    if stage == "aggregate count" {
        return Ok(AggregateSpec::count());
    }
    let columns = stage
        .strip_prefix("aggregate count by ")
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    parse_projection(&columns.split_ascii_whitespace().collect::<Vec<_>>())
        .map(AggregateSpec::count_by)
}

fn parse_ordering(axis: TemporalAxis, specification: &str) -> Result<OrderSpec, QueryFailure> {
    let tokens = specification.split_ascii_whitespace().collect::<Vec<_>>();
    let &[primary, primary_direction, commit, commit_direction] = tokens.as_slice() else {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    };
    let primary_direction = parse_direction(
        primary_direction
            .strip_suffix(',')
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?,
    )?;
    let commit_direction = parse_direction(commit_direction)?;
    let expected_axis = match axis {
        TemporalAxis::QueryTime => "query_time",
        TemporalAxis::EventTime => "event_time",
        TemporalAxis::IngestTime => "ingest_time",
    };
    if primary != expected_axis || commit != "commit_position" {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    Ok(OrderSpec::new(primary_direction, commit_direction))
}

fn parse_direction(source: &str) -> Result<OrderDirection, QueryFailure> {
    match source {
        "asc" => Ok(OrderDirection::Ascending),
        "desc" => Ok(OrderDirection::Descending),
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}
