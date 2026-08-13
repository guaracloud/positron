//! Native bounded query planning and execution.

#![forbid(unsafe_code)]

mod budget;
mod cursor;
mod execution;
mod failure;
mod plan;
mod service;
mod stream;

pub use budget::QueryBudget;
pub use cursor::QueryCursor;
pub use failure::{QueryFailure, QueryFailureCode};
pub use plan::{LogicalPlan, PlannedQuery};
pub use service::{CursorKey, QueryService};
pub use stream::{
    QueryBatch, QueryEvent, QueryHeader, QueryRecord, QueryStats, QueryStream, QueryTerminal,
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
    if let Ok(cursor) = QueryCursor::from_bytes(data)
        && let Ok(key) = CursorKey::new(1, [0xA5; 32])
    {
        let _ = cursor::decode(&key.key, key.epoch, &cursor);
    }
}
