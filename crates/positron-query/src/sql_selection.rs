use crate::plan::{FilterPredicate, ProjectionColumn};
use crate::transform::{BodyTransform, CastTarget};
use crate::{QueryFailure, QueryFailureCode};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Selection {
    Projection {
        projection: crate::planning_memory::PlanningVec<ProjectionColumn>,
        transform: Option<BodyTransform>,
    },
    Count,
    CountBy(crate::planning_memory::PlanningVec<ProjectionColumn>),
}

#[derive(Clone, Copy)]
pub(crate) enum IdentifierCase {
    Exact,
    Insensitive,
}

pub(crate) fn push_column(
    columns: &mut crate::planning_memory::PlanningVec<ProjectionColumn>,
    token: &str,
    case: IdentifierCase,
) -> Result<(), QueryFailure> {
    if token.is_empty() || columns.len() >= 5 {
        return Err(unsupported());
    }
    let matches = |expected: &str| match case {
        IdentifierCase::Exact => token == expected,
        IdentifierCase::Insensitive => token.eq_ignore_ascii_case(expected),
    };
    let column = if matches("body") {
        ProjectionColumn::Body
    } else if matches("query_time") {
        ProjectionColumn::QueryTime
    } else if matches("event_time") {
        ProjectionColumn::EventTime
    } else if matches("ingest_time") {
        ProjectionColumn::IngestTime
    } else if matches("commit_position") {
        ProjectionColumn::CommitPosition
    } else {
        ProjectionColumn::Attribute(crate::attribute_syntax::parse_path(
            token,
            &columns.memory(),
        )?)
    };
    if columns.contains(&column) {
        return Err(unsupported());
    }
    columns.push(column)?;
    Ok(())
}

pub(crate) fn parse_transform(token: &str) -> Result<Option<BodyTransform>, QueryFailure> {
    let Some(open) = token.find('(') else {
        return Ok(None);
    };
    let name = token.get(..open).ok_or_else(unsupported)?;
    let is_json = name.eq_ignore_ascii_case("json");
    let is_logfmt = name.eq_ignore_ascii_case("logfmt");
    let is_cast = name.eq_ignore_ascii_case("cast");
    if !is_json && !is_logfmt && !is_cast {
        return Ok(None);
    }
    let arguments = token.get(open + 1..).ok_or_else(unsupported)?;
    let arguments = arguments.strip_suffix(')').ok_or_else(unsupported)?;
    if is_json || is_logfmt {
        if !arguments.eq_ignore_ascii_case("body") {
            return Err(unsupported());
        }
        return Ok(Some(if is_json {
            BodyTransform::Json
        } else {
            BodyTransform::Logfmt
        }));
    }
    let mut parts = arguments.split_ascii_whitespace();
    let body = parts.next().ok_or_else(unsupported)?;
    let as_keyword = parts.next().ok_or_else(unsupported)?;
    let target = parts.next().ok_or_else(unsupported)?;
    if parts.next().is_some()
        || !body.eq_ignore_ascii_case("body")
        || !as_keyword.eq_ignore_ascii_case("as")
    {
        return Err(unsupported());
    }
    let target = match target {
        value if value.eq_ignore_ascii_case("string") => CastTarget::String,
        value if value.eq_ignore_ascii_case("int") => CastTarget::Integer,
        value if value.eq_ignore_ascii_case("float") => CastTarget::Float,
        value if value.eq_ignore_ascii_case("bool") => CastTarget::Boolean,
        _ => return Err(unsupported()),
    };
    Ok(Some(BodyTransform::Cast(target)))
}

pub(crate) fn parse_body_predicate(
    operator: &str,
    literal: &str,
    memory: &crate::planning_memory::PlanningMemory,
) -> Result<FilterPredicate, QueryFailure> {
    if operator.eq_ignore_ascii_case("=") || operator == "==" {
        return Ok(FilterPredicate::BodyEquals(
            crate::native_literal::parse_body(literal, memory)?,
        ));
    }
    let value = crate::native_literal::parse_search_string(literal, memory)?;
    let retained = u64::try_from(
        value
            .retained_heap_bytes()
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?,
    )
    .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let Some(text_source) = value.as_str() else {
        memory.release_retained(retained)?;
        return Err(unsupported());
    };
    let text_bytes = u64::try_from(text_source.len())
        .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
    let text_memory = memory.reserve(text_bytes)?;
    let text = text_source.to_owned();
    if operator.eq_ignore_ascii_case("contains") {
        let search = crate::search::search_text(text);
        drop(value);
        drop(text_memory);
        memory.release_retained(retained)?;
        let search = search?;
        return Ok(FilterPredicate::BodyContains(search));
    }
    if operator.eq_ignore_ascii_case("regexp")
        || operator.eq_ignore_ascii_case("regex")
        || operator == "~"
    {
        let regex = crate::search::BoundedRegex::from_source(text);
        drop(value);
        drop(text_memory);
        memory.release_retained(retained)?;
        let regex = regex?;
        return Ok(FilterPredicate::BodyRegex(regex));
    }
    drop(value);
    drop(text_memory);
    memory.release_retained(retained)?;
    Err(unsupported())
}

fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_body_search_operator_releases_its_temporary_value() {
        let memory = crate::planning_memory::PlanningMemory::new(1_024);
        let failure =
            parse_body_predicate("like", "\"needle\"", &memory).expect_err("unknown operator");
        assert_eq!(failure.code(), QueryFailureCode::UnsupportedQuery);
    }
}
