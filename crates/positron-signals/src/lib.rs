//! Native signal stores.
//!
//! The Log Store owns canonical native-log encoding and bounded scans over the
//! kernel's authenticated active-segment ledger. Trace storage is deferred.

#![forbid(unsafe_code)]

mod log_store;

pub use log_store::{
    AttributeRepresentation, LogMetadata, LogRecord, LogScan, LogScanResult, LogStore,
    LogStoreFailure, LogStoreFailureCode, PolicyProvenance, PreparedLogBlock, ScanLimit,
    ScannedLogRecord, StoredLogAttribute, StoredLogRecord,
};

#[cfg(fuzzing)]
#[doc(hidden)]
pub use log_store::fuzz_log_store_block;
