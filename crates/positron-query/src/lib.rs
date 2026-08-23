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
mod transform;

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
    let Ok(mut substring) = search::BoundedSubstring::from_source(pattern.to_owned()) else {
        return;
    };
    if substring.compile().is_err() {
        return;
    }
    let _ = substring.is_match_observed(body, &mut observer);
    let literals = regex
        .pruning_literals()
        .iter()
        .map(|literal| literal.to_vec())
        .collect::<Vec<_>>();
    positron_signals::fuzz_text_search_pruning(body, &literals);
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_query_transforms(data: &[u8]) {
    if data.len() > 65_536 {
        return;
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = positron_domain::value::CandidateAttributeValue::string(source.to_owned())
        .validate_log_body(positron_domain::value::ValueLimitProfile::release_1_system_maximum())
    else {
        return;
    };
    struct Unobserved;
    impl transform::TransformObserver for Unobserved {
        fn step(&mut self) -> Result<(), QueryFailure> {
            Ok(())
        }
    }
    for transform in [
        transform::BodyTransform::Json,
        transform::BodyTransform::Logfmt,
        transform::BodyTransform::Cast(transform::CastTarget::String),
        transform::BodyTransform::Cast(transform::CastTarget::Integer),
        transform::BodyTransform::Cast(transform::CastTarget::Float),
        transform::BodyTransform::Cast(transform::CastTarget::Boolean),
    ] {
        let mut observer = Unobserved;
        let _ = transform.apply(&value, &mut observer);
    }
}
