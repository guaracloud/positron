use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate,
    CandidateAttributeValue, ValueLimitProfile,
};

use super::TraceStoreFailure;

/// One bounded typed event or link attribute occurrence set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanAttributeSet {
    pub(super) occurrences: AttributeOccurrenceSet,
}

impl SpanAttributeSet {
    /// Validates one event or link attribute occurrence set.
    pub fn checked(
        key: String,
        occurrences: Vec<CandidateAttributeValue>,
        profile: ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        Self::checked_with_profile(key, occurrences, &profile)
    }

    /// Validates one attribute occurrence set under the pinned profile.
    pub fn checked_with_profile(
        key: String,
        occurrences: Vec<CandidateAttributeValue>,
        profile: &ValueLimitProfile,
    ) -> Result<Self, TraceStoreFailure> {
        let occurrences =
            AttributeOccurrenceSetCandidate::new(AttributeNamespace::Record, key, occurrences)
                .validate(*profile)
                .map_err(TraceStoreFailure::domain)?;
        Ok(Self { occurrences })
    }

    /// Returns the validated attribute key.
    #[must_use]
    pub fn key(&self) -> &str {
        self.occurrences.key()
    }

    /// Returns the number of preserved typed occurrences.
    #[must_use]
    pub fn len(&self) -> usize {
        self.occurrences.len()
    }

    /// Returns whether this set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.occurrences.is_empty()
    }

    /// Returns one typed occurrence by explicit optional index.
    #[must_use]
    pub fn occurrence(
        &self,
        index: usize,
    ) -> Option<&positron_domain::value::ValidatedAttributeValue> {
        self.occurrences.occurrence(index)
    }
}
