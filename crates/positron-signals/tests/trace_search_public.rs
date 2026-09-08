//! Downstream visibility contract for the bounded trace-search types.

use positron_signals::{TraceByIdResult, TraceSearch};

fn accepts_search(_: TraceSearch) {}

fn accepts_by_id_result(_: &TraceByIdResult<'_>) {}

#[test]
fn bounded_trace_search_types_are_exported_at_the_crate_root() {
    let _ = accepts_search;
    let _ = accepts_by_id_result;
}
