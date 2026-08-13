//! Native ingest orchestration and Receiver Adapters.

#![forbid(unsafe_code)]

mod ingest;
mod otlp_logs;
mod policy;

pub use ingest::{
    CommittedAdmission, IngestFailureCode, IngestOutcome, LogIngest, PartialAdmission,
};
pub use otlp_logs::{
    AuthenticatedOtlpLogsRequest, NativeLogAttribute, NativeLogBatch, NativeLogCandidate,
    OtlpLogsReceiver, ReceiveFailure,
};
pub use policy::IngestPolicy;

#[cfg(test)]
mod tests;
