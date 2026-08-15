//! Native ingest orchestration and Receiver Adapters.

#![forbid(unsafe_code)]

mod ingest;
mod loki_push;
mod otlp_logs;
mod planning;
mod request_outcome;
mod schema_catalog;
mod schema_replay;
mod schema_session;

pub use ingest::{
    CommittedAdmission, IngestFailureCode, IngestOutcome, LogIngest, PartialAdmission,
    RejectionDetail,
};
pub use loki_push::{AuthenticatedLokiPushRequest, LokiPushReceiver, LokiPushRequestEncoding};
pub use otlp_logs::{
    AuthenticatedOtlpLogsRequest, NativeLogAdmissionGroup, NativeLogAdmissionGroups,
    NativeLogBatch, OtlpLogsReceiver, OtlpLogsRequestEncoding, ReceiveFailure,
    preflight_otlp_logs_json, preflight_otlp_logs_protobuf, reserve_log_receiver_transport,
    reserve_otlp_logs_transport,
};
pub use planning::{AdmissionGroupPlanFailure, AdmissionGroupPlanner, FixedAdmissionGroupPlanner};
pub use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyAction,
    PolicyAttributePath, PolicyCompileFailure, PolicyEvaluation, PolicyEvaluationFailure,
    PolicyPredicate, PolicyReceiver, PolicyRule, PolicyTarget,
};
pub use positron_signals::{SchemaBudget, SchemaDiscovery, SchemaDiscoveryRequest};
pub use request_outcome::{AdmissionGroupOutcome, IngestRequestOutcome};
pub use schema_catalog::{SchemaCatalogLoadFailure, load_schema_checkpoint};
pub use schema_replay::SchemaReplayBuilder;
pub use schema_session::{
    SchemaSessionFailure, TenantSchemaCheckpoint, TenantSchemaRegistry, TenantSchemaSession,
};

#[cfg(test)]
mod tests;
