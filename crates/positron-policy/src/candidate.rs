use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};

use crate::{LogMetadata, PolicyProvenance};

/// One producer-native dynamic attribute before policy and semantic limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLogAttribute {
    namespace: AttributeNamespace,
    key: String,
    occurrences: Vec<CandidateAttributeValue>,
}

impl NativeLogAttribute {
    #[must_use]
    pub const fn new(
        namespace: AttributeNamespace,
        key: String,
        occurrences: Vec<CandidateAttributeValue>,
    ) -> Self {
        Self {
            namespace,
            key,
            occurrences,
        }
    }

    #[must_use]
    pub const fn namespace(&self) -> AttributeNamespace {
        self.namespace
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn occurrences(&self) -> &[CandidateAttributeValue] {
        &self.occurrences
    }

    #[must_use]
    pub fn into_parts(self) -> (AttributeNamespace, String, Vec<CandidateAttributeValue>) {
        (self.namespace, self.key, self.occurrences)
    }

    pub(crate) fn occurrences_mut(&mut self) -> &mut Vec<CandidateAttributeValue> {
        &mut self.occurrences
    }
}

/// One structurally decoded producer-native Log awaiting policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLogCandidate {
    event_time_unix_nanos: Option<i64>,
    observed_time_unix_nanos: Option<i64>,
    body: Option<CandidateAttributeValue>,
    attributes: Vec<NativeLogAttribute>,
    metadata: LogMetadata,
}

impl NativeLogCandidate {
    #[must_use]
    pub const fn new(
        event_time_unix_nanos: Option<i64>,
        observed_time_unix_nanos: Option<i64>,
        body: Option<CandidateAttributeValue>,
        attributes: Vec<NativeLogAttribute>,
        metadata: LogMetadata,
    ) -> Self {
        Self {
            event_time_unix_nanos,
            observed_time_unix_nanos,
            body,
            attributes,
            metadata,
        }
    }

    #[must_use]
    pub const fn event_time_unix_nanos(&self) -> Option<i64> {
        self.event_time_unix_nanos
    }

    #[must_use]
    pub const fn observed_time_unix_nanos(&self) -> Option<i64> {
        self.observed_time_unix_nanos
    }

    #[must_use]
    pub const fn body(&self) -> Option<&CandidateAttributeValue> {
        self.body.as_ref()
    }

    pub(crate) fn body_mut(&mut self) -> &mut Option<CandidateAttributeValue> {
        &mut self.body
    }

    #[must_use]
    pub fn attributes(&self) -> &[NativeLogAttribute] {
        &self.attributes
    }

    pub(crate) fn attributes_mut(&mut self) -> &mut Vec<NativeLogAttribute> {
        &mut self.attributes
    }

    #[must_use]
    pub const fn metadata(&self) -> &LogMetadata {
        &self.metadata
    }
}

/// A producer-native record after the bounded policy transition.
///
/// Its fields are private so callers cannot bypass policy evaluation before
/// Signal Store semantic validation and preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedLogRecord {
    candidate: NativeLogCandidate,
    provenance: PolicyProvenance,
}

impl EvaluatedLogRecord {
    pub(crate) const fn new(candidate: NativeLogCandidate, provenance: PolicyProvenance) -> Self {
        Self {
            candidate,
            provenance,
        }
    }

    #[must_use]
    pub const fn policy_provenance(&self) -> &PolicyProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn attributes(&self) -> &[NativeLogAttribute] {
        self.candidate.attributes()
    }

    pub fn into_parts(
        self,
    ) -> (
        Option<i64>,
        Option<i64>,
        Option<CandidateAttributeValue>,
        Vec<NativeLogAttribute>,
        LogMetadata,
        PolicyProvenance,
    ) {
        let NativeLogCandidate {
            event_time_unix_nanos,
            observed_time_unix_nanos,
            body,
            attributes,
            metadata,
        } = self.candidate;
        (
            event_time_unix_nanos,
            observed_time_unix_nanos,
            body,
            attributes,
            metadata,
            self.provenance,
        )
    }
}
