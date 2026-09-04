//! Bounded producer-neutral Ingest Policy and its opaque evaluated-record transition.

mod activation;
mod candidate;
mod metadata;
mod policy;
mod provenance;

pub use activation::{
    ActivatedPolicyObject, MAX_ACTIVATED_POLICY_OBJECT_BYTES, PolicyActivationFailure,
};
pub use candidate::{
    EvaluatedLogRecord, EvaluatedTraceRecord, NativeLogAttribute, NativeLogCandidate,
    NativePolicyAttribute, NativeTraceCandidate,
};
pub use metadata::LogMetadata;
pub use policy::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyBudget, PolicyCompileFailure,
    PolicyEvaluation, PolicyEvaluationFailure, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget, TracePolicyEvaluation,
};
pub use provenance::{PolicyProvenance, PolicyProvenanceFailure};
