use crate::plan::{AggregateSpec, FilterPredicate, OrderDirection, OrderSpec, ProjectionColumn};
use crate::transform::{BodyTransform, CastTarget};
use crate::{LogicalPlan, QueryFailure, QueryFailureCode, TemporalAxis};

use crate::sql::plan;

pub(crate) fn parse_pipeline(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<LogicalPlan, QueryFailure> {
    let stages = pipeline_stages(source, memory)?;
    if let Some((&"pipeline:v1 logs", remaining)) = stages.as_slice().split_first() {
        return parse_versioned_pipeline(remaining, memory);
    }
    match stages.as_slice() {
        ["logs", range, limit] => {
            let range = crate::planning_memory::split_ascii_whitespace(range, memory)?;
            let limit = crate::planning_memory::split_ascii_whitespace(limit, memory)?;
            match (range.as_slice(), limit.as_slice()) {
                (["range", axis, start, end], ["limit", limit]) => {
                    let limit = crate::sql::parse_tail_limit(limit)?;
                    plan(axis, start, end, limit, memory)
                },
                _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
            }
        },
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}

fn pipeline_stages<'source>(
    source: &'source str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<crate::planning_memory::PlanningVec<&'source str>, QueryFailure> {
    let capacity = source
        .bytes()
        .filter(|byte| *byte == b'|')
        .count()
        .checked_add(1)
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    let mut stages = crate::planning_memory::PlanningVec::with_capacity(memory, capacity)?;
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
                    stages.push(stage.trim())?;
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
    stages.push(stage.trim())?;
    Ok(stages)
}

fn parse_versioned_pipeline(
    remaining_stages: &[&str],
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<LogicalPlan, QueryFailure> {
    let mut range = None;
    let mut filter = None;
    let mut projection = None;
    let mut aggregate = None;
    let mut ordering = None;
    let mut transform = None;
    let mut limit = None;
    let mut stage_order = 0_u8;
    for &stage in remaining_stages {
        if limit.is_some() || (!stage.starts_with("range ") && range.is_none()) {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
        if let Some(arguments) = stage.strip_prefix("range ") {
            let tokens = crate::planning_memory::split_ascii_whitespace(arguments, memory)?;
            let &[axis, start, end] = tokens.as_slice() else {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            };
            if range.is_some() || stage_order != 0 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            range = Some((axis, start, end));
            stage_order = 1;
        } else if let Some(literal) = stage.strip_prefix("filter body == ") {
            if filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(FilterPredicate::BodyEquals(
                crate::native_literal::parse_body(literal, memory)?,
            ));
            stage_order = 2;
        } else if let Some(predicate) = stage.strip_prefix("filter ") {
            if filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(FilterPredicate::AttributeEquals(
                crate::attribute_syntax::parse_predicate(predicate, memory)?,
            ));
            stage_order = 2;
        } else if let Some(literal) = stage.strip_prefix("search body == ") {
            if filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(FilterPredicate::BodyEquals(
                crate::native_literal::parse_search_string(literal, memory)?,
            ));
            stage_order = 2;
        } else if let Some(literal) = stage.strip_prefix("search body contains ") {
            if filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(crate::search_transfer::parse_filter(
                literal,
                crate::search_transfer::SearchKind::Contains,
                memory,
            )?);
            stage_order = 2;
        } else if let Some(literal) = stage
            .strip_prefix("search body =~ ")
            .or_else(|| stage.strip_prefix("search body ~= "))
        {
            if filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            filter = Some(crate::search_transfer::parse_filter(
                literal,
                crate::search_transfer::SearchKind::Regex,
                memory,
            )?);
            stage_order = 2;
        } else if let Some(columns) = stage.strip_prefix("project ") {
            if projection.is_some() || aggregate.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            projection = Some(parse_projection(columns, memory)?);
            stage_order = 3;
        } else if stage == "aggregate count" || stage.starts_with("aggregate count by ") {
            if projection.is_some() || aggregate.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            aggregate = Some(parse_aggregate(stage, memory)?);
            stage_order = 3;
        } else if stage == "json" {
            if transform.is_some() || filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            transform = Some(BodyTransform::Json);
            stage_order = 2;
        } else if stage == "logfmt" {
            if transform.is_some() || filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            transform = Some(BodyTransform::Logfmt);
            stage_order = 2;
        } else if let Some(target) = stage.strip_prefix("cast body as ") {
            if transform.is_some() || filter.is_some() || stage_order > 2 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            transform = Some(BodyTransform::Cast(parse_cast_target(target)?));
            stage_order = 2;
        } else if let Some(specification) = stage.strip_prefix("order by ") {
            if ordering.is_some() || aggregate.is_some() || stage_order > 3 {
                return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
            }
            ordering = Some(specification);
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
        crate::sql::parse_tail_limit(
            limit.ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?,
        )?,
        memory,
    )?;
    if let Some(filter) = filter {
        plan = plan.with_filter(filter);
    }
    if let Some(transform) = transform {
        plan = plan.with_transform(transform);
    }
    if let Some(projection) = projection {
        plan = plan.with_projection(projection.into_vec());
    }
    if let Some(aggregate) = aggregate {
        plan = plan.with_aggregate(aggregate);
    }
    if let Some(ordering) = ordering {
        let parsed = parse_ordering(plan.temporal_axis(), ordering, memory)?;
        plan = plan.with_explicit_ordering(parsed);
    }
    Ok(plan)
}

fn parse_cast_target(source: &str) -> Result<CastTarget, QueryFailure> {
    match source {
        "string" => Ok(CastTarget::String),
        "int" => Ok(CastTarget::Integer),
        "float" => Ok(CastTarget::Float),
        "bool" => Ok(CastTarget::Boolean),
        _ => Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery)),
    }
}

pub(crate) fn parse_sql(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<LogicalPlan, QueryFailure> {
    crate::sql::parse(source, memory)
}

fn parse_projection(
    source: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<crate::planning_memory::PlanningVec<ProjectionColumn>, QueryFailure> {
    let mut projection = crate::planning_memory::PlanningVec::with_capacity(memory, 5)?;
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
                    crate::sql_selection::push_column(
                        &mut projection,
                        column.trim(),
                        crate::sql_selection::IdentifierCase::Exact,
                    )?;
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
    crate::sql_selection::push_column(
        &mut projection,
        column.trim(),
        crate::sql_selection::IdentifierCase::Exact,
    )?;
    Ok(projection)
}

fn parse_aggregate(
    stage: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<AggregateSpec, QueryFailure> {
    if stage == "aggregate count" {
        return Ok(AggregateSpec::count());
    }
    let columns = stage
        .strip_prefix("aggregate count by ")
        .ok_or_else(|| QueryFailure::new(QueryFailureCode::UnsupportedQuery))?;
    parse_projection(columns, memory).map(|columns| AggregateSpec::count_by(columns.into_vec()))
}

fn parse_ordering(
    axis: TemporalAxis,
    specification: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<OrderSpec, QueryFailure> {
    let tokens = crate::planning_memory::split_ascii_whitespace(specification, memory)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_transforms_are_rejected_before_plan_construction() {
        let memory = crate::planning_memory::PlanningMemory::new(1_024);
        let source = "pipeline:v1 logs | range query_time -100 100 | json | logfmt | limit 1";
        assert!(parse_pipeline(source, &memory).is_err());
    }
}
