use crate::{QueryFailure, QueryFailureCode};

pub(crate) fn parse_limit(source: &str) -> Result<u16, QueryFailure> {
    if source.starts_with('0') && source.len() > 1 {
        return Err(unsupported());
    }
    source.parse().map_err(|_| unsupported())
}

pub(crate) fn parse_timestamp(source: &str) -> Result<i64, QueryFailure> {
    if source.starts_with('+')
        || (source.starts_with('0') && source.len() > 1)
        || (source.starts_with("-0") && source.len() > 2)
    {
        return Err(unsupported());
    }
    source.parse().map_err(|_| unsupported())
}

pub(crate) fn clause(token: &str) -> bool {
    ["group", "order", "limit"]
        .iter()
        .any(|value| token.eq_ignore_ascii_case(value))
}

pub(crate) fn is_count_group(value: &str) -> bool {
    let Some(value) = value
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    value.trim_matches(|character: char| character.is_ascii_whitespace()) == "*"
}

pub(crate) const fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}
