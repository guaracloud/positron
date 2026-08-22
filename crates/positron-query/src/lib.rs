//! Native bounded query planning and execution.

#![forbid(unsafe_code)]

mod attribute_syntax;
mod budget;
mod cancellation;
mod cursor;
mod execution;
mod execution_state;
mod execution_support;
mod failure;
mod memory;
mod native_literal;
mod operators;
mod plan;
mod query_service;
mod runtime;
mod search;
mod service;
mod stream;
mod stream_lifecycle;

pub use budget::{QueryBudget, QueryBudgetDimension};
pub use cancellation::QueryCancellation;
pub use cursor::QueryCursor;
pub use failure::{QueryFailure, QueryFailureCode};
pub use plan::{LogicalPlan, OrderDirection, PlannedQuery, TemporalAxis, TemporalRange};
pub use query_service::QueryService;
pub use runtime::{
    QueryClock, QueryClockFailure, QueryWorkFailure, QueryWorkMeter, QueryWorkStage,
};
pub use stream::{
    QueryBatch, QueryEvent, QueryHeader, QueryIncomplete, QueryRecord, QueryStats, QueryTerminal,
    ResultLease, ResultOrdering, ResultSchema, ResultSnapshot, ResultValueType,
};
pub use stream_lifecycle::QueryStream;

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_inputs(data: &[u8]) {
    if data.len() > 4_096 {
        return;
    }
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = service::parse_pipeline(source);
        let _ = service::parse_sql(source);
    }
    let _ = QueryCursor::from_bytes(data);
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_search_matcher(data: &[u8]) {
    if data.is_empty() || data.len() > 4_096 {
        return;
    }
    let pattern_len = usize::from(data[0]).min(data.len().saturating_sub(1));
    let (pattern, body) = data[1..].split_at(pattern_len);
    let Ok(pattern) = std::str::from_utf8(pattern) else {
        return;
    };
    let Ok(body) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(mut regex) = search::BoundedRegex::from_source(pattern.to_owned()) else {
        return;
    };
    if regex.compile().is_err() {
        return;
    }
    let mut observer = search::UnobservedSearch;
    let _ = regex.is_match_observed(body, &mut observer);
    let _ = search::contains_observed(body, pattern, &mut observer);
    let literals = regex
        .pruning_literals()
        .iter()
        .map(|literal| literal.to_vec())
        .collect::<Vec<_>>();
    positron_signals::fuzz_text_search_pruning(body, &literals);
}
