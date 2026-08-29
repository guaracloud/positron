use positron_domain::value::{AttributeOccurrenceSetCandidate, ValueLimitProfile};

use super::LogRecord;
use crate::log_store::LogStoreFailure;

impl LogRecord {
    /// Applies semantic limits to the opaque output of Ingest Policy.
    pub fn checked_evaluated(
        profile: ValueLimitProfile,
        evaluated: positron_policy::EvaluatedLogRecord,
    ) -> Result<Self, LogStoreFailure> {
        let (event_time, observed_time, body, attributes, metadata, evaluated_policy) =
            evaluated.into_parts();
        let attributes = attributes
            .into_iter()
            .map(|attribute| {
                let (namespace, key, occurrences) = attribute.into_parts();
                AttributeOccurrenceSetCandidate::new(namespace, key, occurrences)
            })
            .collect();
        Self::checked_receiver_candidate_with_metadata(
            profile,
            event_time,
            observed_time,
            body,
            attributes,
            metadata,
            evaluated_policy,
        )
    }
}
