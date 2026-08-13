//! Native bounded query planning and execution.

#![forbid(unsafe_code)]

mod budget;
mod cursor;
mod execution;
mod execution_state;
mod execution_support;
mod failure;
mod plan;
mod runtime;
mod service;
mod stream;

pub use budget::QueryBudget;
pub use cursor::QueryCursor;
pub use failure::{QueryFailure, QueryFailureCode};
pub use plan::{LogicalPlan, PlannedQuery, TemporalAxis, TemporalRange};
pub use runtime::{
    QueryClock, QueryClockFailure, QueryWorkFailure, QueryWorkMeter, QueryWorkStage,
};
pub use service::QueryService;
pub use stream::{
    QueryBatch, QueryEvent, QueryHeader, QueryIncomplete, QueryRecord, QueryStats, QueryStream,
    QueryTerminal, ResultLease, ResultOrdering, ResultSchema, ResultSnapshot,
};

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
