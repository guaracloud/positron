//! Native ingest orchestration and Receiver Adapters.

#![forbid(unsafe_code)]

mod ingest;
mod otlp_logs;
mod planning;
mod policy;
mod request_outcome;

pub use ingest::{
    CommittedAdmission, IngestFailureCode, IngestOutcome, LogIngest, PartialAdmission,
    RejectionDetail,
};
pub use otlp_logs::{
    AuthenticatedOtlpLogsRequest, NativeLogAdmissionGroup, NativeLogAdmissionGroups,
    NativeLogAttribute, NativeLogBatch, NativeLogCandidate, OtlpLogsReceiver, ReceiveFailure,
    reserve_otlp_logs_transport,
};
pub use planning::{AdmissionGroupPlanFailure, AdmissionGroupPlanner, FixedAdmissionGroupPlanner};
pub use policy::IngestPolicy;
pub use request_outcome::{AdmissionGroupOutcome, IngestRequestOutcome};

#[cfg(test)]
mod tests;
