//! Bounded producer-neutral Ingest Policy and its opaque evaluated-record transition.

mod activation;
mod administration_preview;
mod candidate;
mod metadata;
mod policy;
mod provenance;

pub use activation::{
    ActivatedPolicyObject, MAX_ACTIVATED_POLICY_OBJECT_BYTES, PolicyActivationFailure,
};
pub use administration_preview::{
    PolicyPreview, PolicyPreviewCandidate, PolicyPreviewDiff, PolicyPreviewFailure,
    PolicyPreviewOutcome, PolicyPreviewPolicy, PolicyPreviewResult, PolicyPreviewSemanticChange,
    PolicyPreviewValidation,
};
pub use candidate::{
    EvaluatedLogRecord, EvaluatedTraceRecord, NativeLogAttribute, NativeLogCandidate,
    NativePolicyAttribute, NativeTraceCandidate,
};
pub use metadata::LogMetadata;
pub use policy::{
    IngestPolicy, PolicyAction, PolicyAdmissionShape, PolicyAttributePath, PolicyBudget,
    PolicyCompileFailure, PolicyEvaluation, PolicyEvaluationFailure, PolicyPredicate,
    PolicyReceiver, PolicyRule, PolicyTarget, TracePolicyEvaluation,
};
pub use provenance::{ObservedPolicyProvenanceFailure, PolicyProvenance, PolicyProvenanceFailure};
