//! Native ingest orchestration and Receiver Adapters.

#![forbid(unsafe_code)]

mod ingest;
mod loki_push;
mod otlp_logs;
mod planning;
mod policy;
mod request_outcome;

pub use ingest::{
    CommittedAdmission, IngestFailureCode, IngestOutcome, LogIngest, PartialAdmission,
    RejectionDetail,
};
pub use loki_push::{AuthenticatedLokiPushRequest, LokiPushReceiver, LokiPushRequestEncoding};
pub use otlp_logs::{
    AuthenticatedOtlpLogsRequest, NativeLogAdmissionGroup, NativeLogAdmissionGroups,
    NativeLogAttribute, NativeLogBatch, NativeLogCandidate, OtlpLogsReceiver,
    OtlpLogsRequestEncoding, ReceiveFailure, preflight_otlp_logs_json,
    preflight_otlp_logs_protobuf, reserve_log_receiver_transport, reserve_otlp_logs_transport,
};
pub use planning::{AdmissionGroupPlanFailure, AdmissionGroupPlanner, FixedAdmissionGroupPlanner};
pub use policy::{
    IngestPolicy, IngestPolicyAuthority, IngestPolicySnapshot, PolicyAction, PolicyAttributePath,
    PolicyCompileFailure, PolicyPredicate, PolicyPublicationFailure, PolicyReceiver, PolicyRule,
    PolicyTarget,
};
pub use request_outcome::{AdmissionGroupOutcome, IngestRequestOutcome};

#[cfg(test)]
mod tests;
