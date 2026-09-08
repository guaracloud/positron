//! Downstream visibility contract for the bounded trace-search types.

use positron_signals::{
    TraceByIdResult, TraceCriticalPath, TraceCriticalPathFragment, TraceSearch, TraceStructure,
    TraceStructureIncompleteness,
};

fn accepts_search(_: TraceSearch) {}

fn accepts_by_id_result(_: &TraceByIdResult<'_>) {}

fn accepts_structure(_: &TraceStructure<'_>) {}

fn accepts_incompleteness(_: TraceStructureIncompleteness) {}

fn accepts_critical_path(_: &TraceCriticalPath) {}

fn accepts_fragment(_: TraceCriticalPathFragment) {}

#[test]
fn bounded_trace_search_types_are_exported_at_the_crate_root() {
    let _ = accepts_search;
    let _ = accepts_by_id_result;
    let _ = accepts_structure;
    let _ = accepts_incompleteness;
    let _ = accepts_critical_path;
    let _ = accepts_fragment;
}
