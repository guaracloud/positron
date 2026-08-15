//! Native signal stores.
//!
//! The Log Store owns canonical native-log encoding and bounded scans over the
//! kernel's authenticated active-segment ledger. Trace storage is deferred.

#![forbid(unsafe_code)]

mod log_store;

pub use log_store::{
    AttributeRepresentation, LogMetadata, LogRecord, LogScan, LogScanResult, LogStore,
    LogStoreFailure, LogStoreFailureCode, OccurrenceSelector, PolicyProvenance, PreparedLogBlock,
    ScanLimit, ScannedLogRecord, SchemaBudget, SchemaBudgetPressure, SchemaCatalog,
    SchemaCheckpointFrontier, SchemaDelta, SchemaDiscovery, SchemaDiscoveryRequest, SchemaEntry,
    SchemaFailure, SchemaMutationPermit, SchemaObservation, SchemaPath, SchemaPathDigest,
    SchemaPathSummary, SchemaPromotionDecision, SchemaPromotionReason, SchemaQuery,
    SchemaQueryResult, SchemaRepresentation, SchemaValue, StoredLogAttribute, StoredLogRecord,
    TenantSchemaState,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub use log_store::fuzz_log_store_block;
