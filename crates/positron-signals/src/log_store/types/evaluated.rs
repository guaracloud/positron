use positron_domain::value::{AttributeOccurrenceSetCandidate, ValueLimitProfile};

use super::LogRecord;
use crate::log_store::{LogStoreFailure, PolicyProvenance};

impl LogRecord {
    /// Applies semantic limits to the opaque output of Ingest Policy.
    pub fn checked_evaluated(
        profile: ValueLimitProfile,
        evaluated: positron_policy::EvaluatedLogRecord,
    ) -> Result<Self, LogStoreFailure> {
        let (event_time, observed_time, body, attributes, metadata, evaluated_policy) =
            evaluated.into_parts();
        let policy = PolicyProvenance::from_evaluated(&evaluated_policy)?;
        let attributes = attributes
            .into_iter()
            .map(|attribute| {
                AttributeOccurrenceSetCandidate::new(
                    attribute.namespace(),
                    attribute.key().to_owned(),
                    attribute.occurrences().to_vec(),
                )
            })
            .collect();
        Self::checked_receiver_candidate_with_metadata(
            profile,
            event_time,
            observed_time,
            body,
            attributes,
            metadata,
            policy,
        )
    }
}
