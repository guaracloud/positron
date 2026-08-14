//! Bounded producer-neutral Ingest Policy and its opaque evaluated-record transition.

mod activation;
mod candidate;
mod metadata;
mod policy;
mod provenance;

pub use activation::{
    ActivatedPolicyObject, MAX_ACTIVATED_POLICY_OBJECT_BYTES, PolicyActivationFailure,
};
pub use candidate::{EvaluatedLogRecord, NativeLogAttribute, NativeLogCandidate};
pub use metadata::LogMetadata;
pub use policy::{
    IngestPolicy, PolicyAction, PolicyAttributePath, PolicyBudget, PolicyCompileFailure,
    PolicyEvaluation, PolicyEvaluationFailure, PolicyPredicate, PolicyReceiver, PolicyRule,
    PolicyTarget,
};
pub use provenance::PolicyProvenance;
