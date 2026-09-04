use std::fmt::{Display, Formatter};

use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};

pub(crate) mod canonical;
mod compile;
mod evaluation;

pub(crate) const MAX_RULES: usize = 64;
pub(crate) const MAX_PREDICATES_PER_RULE: usize = 16;
pub(crate) const MAX_RULE_ID_BYTES: usize = 256;
pub(crate) const MAX_POLICY_PATH_BYTES: usize = 1_024;
pub(crate) const MAX_COMPILED_POLICY_BYTES: usize = 1_048_576;
pub(crate) const MAX_EVALUATION_STEPS: u64 = 100_000_000;
pub(crate) const MAX_NATIVE_RECORD_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug)]
pub struct IngestPolicy {
    pub(crate) generation: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) rules: Vec<PolicyRule>,
    pub(crate) budget: PolicyBudget,
}

/// Conservative per-record resources reserved before policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyBudget {
    evaluation_steps: u64,
    retained_bytes: u64,
    scratch_bytes: u64,
    provenance_bytes: u64,
    mutation_bytes: u64,
}

impl PolicyBudget {
    #[must_use]
    pub const fn evaluation_steps(self) -> u64 {
        self.evaluation_steps
    }

    #[must_use]
    pub fn reserved_memory_bytes(self) -> Option<u64> {
        self.retained_bytes
            .checked_add(self.scratch_bytes)
            .and_then(|bytes| bytes.checked_add(self.provenance_bytes))
            .and_then(|bytes| bytes.checked_add(self.mutation_bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAttributePath {
    pub(crate) namespace: AttributeNamespace,
    pub(crate) key: String,
    pub(crate) occurrence: PolicyOccurrence,
    pub(crate) segments: Vec<PolicyPathSegment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyOccurrence {
    All,
    Index(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyPathSegment {
    Key(String),
    ArrayIndex(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyPredicate {
    AttributeExists(PolicyAttributePath),
    BodyExactText(String),
    SignalStore(SignalKind),
    Receiver(PolicyReceiver),
    AttributeType(PolicyAttributePath, AttributeValueKind),
    ServiceIdentity(String),
    LogSeverity(i32),
}

/// Exact semantic Receiver Adapter identity; compression does not change it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyReceiver {
    OtlpGrpc,
    OtlpHttpProtobuf,
    OtlpHttpJson,
    LokiPushJson,
    LokiPushProtobuf,
    LokiOtlpProtobuf,
    LokiOtlpJson,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    Accept,
    Reject,
    Remove(PolicyTarget),
    Redact(PolicyTarget),
    TruncateBytes(PolicyTarget, u32),
    TruncateElements(PolicyTarget, u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyTarget {
    Body,
    Attribute(PolicyAttributePath),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub(crate) id: String,
    pub(crate) predicates: Vec<PolicyPredicate>,
    pub(crate) action: PolicyAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCompileFailure {
    InvalidIdentity,
    RuleBoundExceeded,
    PredicateBoundExceeded,
    InvalidRuleId,
    InvalidPath,
    InvalidPredicate,
    PolicyBytesExceeded,
    ProtectedTarget,
    EvaluationBudgetExceeded,
}

impl Display for PolicyCompileFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ingest Policy compilation failed")
    }
}

impl std::error::Error for PolicyCompileFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyEvaluationFailure {
    StepBudgetExhausted,
    EvidenceBoundExceeded,
}

impl Display for PolicyEvaluationFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ingest Policy evaluation failed")
    }
}

impl std::error::Error for PolicyEvaluationFailure {}

#[derive(Debug, Eq, PartialEq)]
pub enum PolicyEvaluation {
    Accepted(Box<crate::EvaluatedLogRecord>),
    Rejected,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TracePolicyEvaluation {
    Accepted(Box<crate::EvaluatedTraceRecord>),
    Rejected,
}

impl PolicyAttributePath {
    pub fn new(
        namespace: AttributeNamespace,
        key: impl Into<String>,
    ) -> Result<Self, PolicyCompileFailure> {
        let key = key.into();
        if key.is_empty() || key.len() > MAX_POLICY_PATH_BYTES {
            return Err(PolicyCompileFailure::InvalidPath);
        }
        Ok(Self {
            namespace,
            key,
            occurrence: PolicyOccurrence::All,
            segments: Vec::new(),
        })
    }

    #[must_use]
    pub const fn at_occurrence(mut self, index: u16) -> Self {
        self.occurrence = PolicyOccurrence::Index(index);
        self
    }

    pub fn key(mut self, key: impl Into<String>) -> Result<Self, PolicyCompileFailure> {
        self.push_segment(PolicyPathSegment::Key(key.into()))?;
        Ok(self)
    }

    pub fn array_index(mut self, index: u16) -> Result<Self, PolicyCompileFailure> {
        self.push_segment(PolicyPathSegment::ArrayIndex(index))?;
        Ok(self)
    }

    fn push_segment(&mut self, segment: PolicyPathSegment) -> Result<(), PolicyCompileFailure> {
        if self.segments.len() == 16 {
            return Err(PolicyCompileFailure::InvalidPath);
        }
        let added = match &segment {
            PolicyPathSegment::Key(key) if key.is_empty() => {
                return Err(PolicyCompileFailure::InvalidPath);
            },
            PolicyPathSegment::Key(key) => key.len(),
            PolicyPathSegment::ArrayIndex(_) => 2,
        };
        if self.bounded_bytes().saturating_add(added) > MAX_POLICY_PATH_BYTES {
            return Err(PolicyCompileFailure::InvalidPath);
        }
        self.segments.push(segment);
        Ok(())
    }

    pub(crate) fn bounded_bytes(&self) -> usize {
        self.segments.iter().fold(self.key.len(), |bytes, segment| {
            bytes.saturating_add(match segment {
                PolicyPathSegment::Key(key) => key.len(),
                PolicyPathSegment::ArrayIndex(_) => 2,
            })
        })
    }
}

impl PolicyTarget {
    #[must_use]
    pub const fn body() -> Self {
        Self::Body
    }

    #[must_use]
    pub const fn attribute(path: PolicyAttributePath) -> Self {
        Self::Attribute(path)
    }
}

impl PolicyPredicate {
    #[must_use]
    pub const fn attribute_exists(path: PolicyAttributePath) -> Self {
        Self::AttributeExists(path)
    }

    pub fn body_exact_text(value: impl Into<String>) -> Result<Self, PolicyCompileFailure> {
        let value = value.into();
        if value.len() > MAX_COMPILED_POLICY_BYTES {
            return Err(PolicyCompileFailure::InvalidPredicate);
        }
        Ok(Self::BodyExactText(value))
    }

    #[must_use]
    pub const fn signal_store(signal: SignalKind) -> Self {
        Self::SignalStore(signal)
    }

    #[must_use]
    pub const fn receiver(receiver: PolicyReceiver) -> Self {
        Self::Receiver(receiver)
    }

    #[must_use]
    pub const fn attribute_type(path: PolicyAttributePath, kind: AttributeValueKind) -> Self {
        Self::AttributeType(path, kind)
    }

    pub fn service_identity(value: impl Into<String>) -> Result<Self, PolicyCompileFailure> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_POLICY_PATH_BYTES {
            return Err(PolicyCompileFailure::InvalidPredicate);
        }
        Ok(Self::ServiceIdentity(value))
    }

    #[must_use]
    pub const fn log_severity(value: i32) -> Self {
        Self::LogSeverity(value)
    }
}

impl PolicyRule {
    pub fn new(
        id: impl Into<String>,
        predicates: Vec<PolicyPredicate>,
        action: PolicyAction,
    ) -> Result<Self, PolicyCompileFailure> {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_RULE_ID_BYTES {
            return Err(PolicyCompileFailure::InvalidRuleId);
        }
        if predicates.len() > MAX_PREDICATES_PER_RULE {
            return Err(PolicyCompileFailure::PredicateBoundExceeded);
        }
        Ok(Self {
            id,
            predicates,
            action,
        })
    }
}
