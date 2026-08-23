use crate::plan::FilterPredicate;
use crate::planning_memory::PlanningMemory;
use crate::planning_string::PlanningString;
use crate::{QueryFailure, QueryFailureCode};

#[derive(Clone, Copy)]
pub(crate) enum SearchKind {
    Contains,
    Regex,
}

pub(crate) fn parse_filter(
    literal: &str,
    kind: SearchKind,
    memory: &PlanningMemory,
) -> Result<FilterPredicate, QueryFailure> {
    let (value, parser_reservation, _) =
        crate::native_literal::parse_search_string_with_reservation(literal, memory)?;
    let source = value.as_str().ok_or_else(unsupported)?;
    if source.is_empty() || source.len() > crate::search::MAX_SEARCH_LITERAL_BYTES {
        drop(value);
        drop(parser_reservation);
        return Err(unsupported());
    }
    let planned = match PlanningString::copy(source, memory) {
        Ok(planned) => planned,
        Err(failure) => {
            drop(value);
            drop(parser_reservation);
            return Err(failure);
        },
    };
    let (source, search_reservation, source_bytes) = match planned.into_parts() {
        Ok(parts) => parts,
        Err(failure) => {
            drop(value);
            drop(parser_reservation);
            return Err(failure);
        },
    };
    let filter = match kind {
        SearchKind::Contains => {
            crate::search::BoundedSubstring::from_source(source).map(FilterPredicate::BodyContains)
        },
        SearchKind::Regex => {
            crate::search::BoundedRegex::from_source(source).map(FilterPredicate::BodyRegex)
        },
    };
    drop(value);
    drop(parser_reservation);
    match filter {
        Ok(filter) => {
            memory.retain_reservation(search_reservation, source_bytes)?;
            Ok(filter)
        },
        Err(failure) => {
            drop(search_reservation);
            Err(failure)
        },
    }
}

fn unsupported() -> QueryFailure {
    QueryFailure::new(QueryFailureCode::UnsupportedQuery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_refusal_releases_the_parser_reservation() {
        let memory = PlanningMemory::new(8);
        let failure = parse_filter(r#""needle""#, SearchKind::Contains, &memory)
            .expect_err("copy must exceed the parser-only budget");
        assert_eq!(failure.code(), QueryFailureCode::BudgetExhausted);
        assert_eq!(memory.take_retained().bytes(), 0);
    }
}
