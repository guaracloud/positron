use crate::plan::ProjectionColumn;
use crate::transform::{BodyTransform, CastTarget};
use crate::{QueryFailure, QueryFailureCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Selection {
    Projection {
        projection: Vec<ProjectionColumn>,
        transform: Option<BodyTransform>,
    },
    Count,
    CountBy(Vec<ProjectionColumn>),
}

pub(crate) fn push_column(
    columns: &mut Vec<ProjectionColumn>,
    token: &str,
) -> Result<(), QueryFailure> {
    if token.is_empty() || columns.len() >= 5 {
        return Err(unsupported());
    }
    let column = if token.eq_ignore_ascii_case("body") {
        ProjectionColumn::Body
    } else if token.eq_ignore_ascii_case("query_time") {
        ProjectionColumn::QueryTime
    } else if token.eq_ignore_ascii_case("event_time") {
        ProjectionColumn::EventTime
    } else if token.eq_ignore_ascii_case("ingest_time") {
        ProjectionColumn::IngestTime
    } else if token.eq_ignore_ascii_case("commit_position") {
        ProjectionColumn::CommitPosition
    } else {
        ProjectionColumn::Attribute(crate::attribute_syntax::parse_path(token)?)
    };
    if columns.contains(&column) {
        return Err(unsupported());
    }
    columns.push(column);
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

fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
