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
