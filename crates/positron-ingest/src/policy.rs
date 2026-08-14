use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::routing::SignalKind;
use positron_domain::value::{AttributeNamespace, AttributeValueKind};
use positron_signals::{LogStoreFailure, PolicyProvenance};

use crate::NativeLogCandidate;

mod authority;
mod compile;
mod evaluation;
pub use authority::{IngestPolicyAuthority, IngestPolicySnapshot, PolicyPublicationFailure};

const MAX_RULES: usize = 64;
const MAX_PREDICATES_PER_RULE: usize = 16;
const MAX_RULE_ID_BYTES: usize = 256;
const MAX_POLICY_PATH_BYTES: usize = 1_024;
const MAX_COMPILED_POLICY_BYTES: usize = 1_048_576;
const RELEASE_1_DEFAULT_POLICY_DIGEST: [u8; 32] = [
    0xd7, 0x16, 0x14, 0x7f, 0xd9, 0xe5, 0xe7, 0xf4, 0xd2, 0x0d, 0xe7, 0x45, 0x05, 0xcb, 0x1b, 0x18,
    0x2f, 0x91, 0x44, 0x17, 0x7d, 0x95, 0xc3, 0x54, 0xd8, 0xb9, 0x9d, 0x29, 0x9c, 0x8f, 0x0f, 0xe1,
];

/// A compiled immutable policy generation safe to snapshot for a request.
#[derive(Clone, Debug)]
pub struct IngestPolicy {
    provenance: PolicyProvenance,
    rules: Vec<PolicyRule>,
}

/// One root attribute path in a source namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAttributePath {
    namespace: AttributeNamespace,
    key: String,
    occurrence: PolicyOccurrence,
    segments: Vec<PolicyPathSegment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyOccurrence {
    All,
    Index(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PolicyPathSegment {
    Key(String),
    ArrayIndex(u16),
}

/// A bounded declarative predicate. Predicates in one rule are conjunctive.
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

/// Stable identity of the Receiver Adapter that produced a native batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyReceiver {
    OtlpLogs,
    LokiPush,
}

/// A Release 1 policy action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    Accept,
    Reject,
    Remove(PolicyTarget),
    Redact(PolicyTarget),
    TruncateBytes(PolicyTarget, u32),
    TruncateElements(PolicyTarget, u16),
}

/// The complete mutable policy surface: producer body content or dynamic attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyTarget {
    Body,
    Attribute(PolicyAttributePath),
}

/// One ordered declarative rule compiled before policy publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    id: String,
    predicates: Vec<PolicyPredicate>,
    action: PolicyAction,
}

/// Stable secret-free policy compilation failure.
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
}

impl Display for PolicyCompileFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Ingest Policy compilation failed")
    }
}

impl Error for PolicyCompileFailure {}

pub(crate) enum PolicyDecision {
    Accept {
        record: Box<NativeLogCandidate>,
        provenance: PolicyProvenance,
    },
    Reject,
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

    /// Selects one source-ordered occurrence instead of every occurrence.
    #[must_use]
    pub const fn at_occurrence(mut self, index: u16) -> Self {
        self.occurrence = PolicyOccurrence::Index(index);
        self
    }

    /// Descends through every matching key in an ordered native key/value list.
    pub fn key(mut self, key: impl Into<String>) -> Result<Self, PolicyCompileFailure> {
        let key = key.into();
        self.push_segment(PolicyPathSegment::Key(key))?;
        Ok(self)
    }

    /// Descends through one explicit source-ordered native array entry.
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
            PolicyPathSegment::ArrayIndex(_) => std::mem::size_of::<u16>(),
        };
        let total = self
            .segments
            .iter()
            .try_fold(self.key.len(), |bytes, segment| {
                bytes.checked_add(match segment {
                    PolicyPathSegment::Key(key) => key.len(),
                    PolicyPathSegment::ArrayIndex(_) => std::mem::size_of::<u16>(),
                })
            })
            .and_then(|bytes| bytes.checked_add(added))
            .ok_or(PolicyCompileFailure::InvalidPath)?;
        if total > MAX_POLICY_PATH_BYTES {
            return Err(PolicyCompileFailure::InvalidPath);
        }
        self.segments.push(segment);
        Ok(())
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

impl IngestPolicy {
    /// Returns the preserving default policy snapshot.
    pub fn release_1_default() -> Result<Self, LogStoreFailure> {
        Self::preserving(1, RELEASE_1_DEFAULT_POLICY_DIGEST)
    }

    #[must_use]
    pub const fn provenance(&self) -> &PolicyProvenance {
        &self.provenance
    }

    pub fn preserving(generation: u64, digest: [u8; 32]) -> Result<Self, LogStoreFailure> {
        Ok(Self {
            provenance: PolicyProvenance::new(generation, digest, Vec::new())?,
            rules: Vec::new(),
        })
    }

    pub fn reject_exact_text_body(
        generation: u64,
        digest: [u8; 32],
        rule_id: &str,
        body: &str,
    ) -> Result<Self, PolicyCompileFailure> {
        let predicate = PolicyPredicate::body_exact_text(body)?;
        let rule = PolicyRule::new(rule_id, vec![predicate], PolicyAction::Reject)?;
        Self::compile(generation, digest, vec![rule])
    }
}
