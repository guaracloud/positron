//! Native signal stores.
//!
//! The Log and Trace Stores own canonical native-signal encoding and bounded
//! scans over the kernel's authenticated active-segment ledger.

#![forbid(unsafe_code)]

mod log_store;
mod trace_store;

pub use log_store::{
    AttributeRepresentation, LogCompactionOutcome, LogMetadata, LogRecord, LogRetentionBucket,
    LogRetentionOutcome, LogRetentionPolicy, LogScan, LogScanResult, LogStore, LogStoreFailure,
    LogStoreFailureCode, OccurrenceSelector, PolicyProvenance, PreparedLogBlock, ScanCancellation,
    ScanLimit, ScanObservationFailureCode, ScanObserver, ScannedLogRecord, SchemaBudget,
    SchemaBudgetPressure, SchemaCatalog, SchemaCheckpointFrontier, SchemaDelta, SchemaDiscovery,
    SchemaDiscoveryRequest, SchemaEntry, SchemaFailure, SchemaObservation, SchemaPath,
    SchemaPathDigest, SchemaPathSummary, SchemaPromotionDecision, SchemaPromotionReason,
    SchemaQuery, SchemaQueryResult, SchemaQueryUpdate, SchemaRepresentation, SchemaSessionStore,
    SchemaTraversalFailure, SchemaValue, StoredLogAttribute, StoredLogRecord, TextSearchCandidate,
};
pub use trace_store::{
    PreparedTraceBlock, SamplingDecision, ScannedSpanObservation, SpanKind, SpanObservation,
    StoredSpanObservation, TraceIncompleteness, TraceScan, TraceScanResult, TraceStore,
    TraceStoreFailure, TraceStoreFailureCode,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub use log_store::{fuzz_log_retention_block, fuzz_log_store_block, fuzz_text_search_pruning};
#[cfg(fuzzing)]
#[doc(hidden)]
pub use trace_store::fuzz_trace_store_block;
