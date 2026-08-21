use crate::plan::{AggregateSpec, FilterPredicate, OrderDirection, OrderSpec, ProjectionColumn};
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, TemporalAxis, TemporalRange};

pub(crate) fn parse_pipeline(source: &str) -> Result<LogicalPlan, QueryFailure> {
    let stages = pipeline_stages(source)?;
    if let Some((&"pipeline:v1 logs", remaining)) = stages.split_first() {
        return parse_versioned_pipeline(remaining);
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

fn parse_versioned_pipeline(remaining_stages: &[&str]) -> Result<LogicalPlan, QueryFailure> {
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
            filter = Some(FilterPredicate::BodyEquals(
                crate::native_literal::parse_body(literal)?,
            ));
            stage_order = 2;
        } else if let Some(predicate) = stage.strip_prefix("filter ") {
            if filter.is_some() || stage_order > 1 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(FilterPredicate::AttributeEquals(
                crate::attribute_syntax::parse_predicate(predicate)?,
            ));
            stage_order = 2;
        } else if let Some(literal) = stage.strip_prefix("search body == ") {
            if filter.is_some() || stage_order > 1 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(FilterPredicate::BodyEquals(
                crate::native_literal::parse_search_string(literal)?,
            ));
            stage_order = 2;
        } else if let Some(columns) = stage.strip_prefix("project ") {
            if projection.is_some() || aggregate.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            projection = Some(parse_projection(columns)?);
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
        plan = plan.with_filter(filter);
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

fn parse_projection(source: &str) -> Result<Vec<ProjectionColumn>, QueryFailure> {
    let mut projection = Vec::new();
    projection
        .try_reserve_exact(5)
        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in source.char_indices() {
        if escaped {
            escaped = false;
        } else {
            match character {
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                ',' if !quoted => {
                    let column = source
                        .get(start..index)
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
                    push_projection_column(&mut projection, column.trim())?;
                    start = index
                        .checked_add(character.len_utf8())
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
                },
                _ => {},
            }
        }
    }
    let column = source
        .get(start..)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    push_projection_column(&mut projection, column.trim())?;
    Ok(projection)
}

fn push_projection_column(
    projection: &mut Vec<ProjectionColumn>,
    column: &str,
) -> Result<(), QueryFailure> {
    if column.is_empty() || projection.len() == 5 {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    let column = match column {
        "body" => ProjectionColumn::Body,
        "query_time" => ProjectionColumn::QueryTime,
        "event_time" => ProjectionColumn::EventTime,
        "ingest_time" => ProjectionColumn::IngestTime,
        "commit_position" => ProjectionColumn::CommitPosition,
        _ => ProjectionColumn::Attribute(crate::attribute_syntax::parse_path(column)?),
    };
    if projection.contains(&column) {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    projection.push(column);
    Ok(())
}

fn parse_aggregate(stage: &str) -> Result<AggregateSpec, QueryFailure> {
    if stage == "aggregate count" {
        return Ok(AggregateSpec::count());
    }
    let columns = stage
        .strip_prefix("aggregate count by ")
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    parse_projection(columns).map(AggregateSpec::count_by)
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
