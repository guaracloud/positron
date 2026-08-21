use positron_domain::value::{AttributeNamespace, ValueLimitProfile};

use crate::log_store::LogStoreFailure;

/// Shared semantic record accumulator used by materializing and validate-only decoding.
pub(in crate::log_store) struct NativeRecordValidator {
    maximum_occurrences: usize,
    decoded_limit: usize,
    decoded_bytes: usize,
    occurrences_by_namespace: [usize; 4],
}

impl NativeRecordValidator {
    pub(in crate::log_store) fn new(profile: ValueLimitProfile) -> Result<Self, LogStoreFailure> {
        let limits = profile.effective_limits();
        Ok(Self {
            maximum_occurrences: usize::try_from(
                limits.dynamic_value().attributes_per_namespace().value(),
            )
            .map_err(|_| LogStoreFailure::limit_exceeded())?,
            decoded_limit: usize::try_from(limits.record().decoded_bytes().value())
                .map_err(|_| LogStoreFailure::limit_exceeded())?,
            decoded_bytes: 0,
            occurrences_by_namespace: [0; 4],
        })
    }

    pub(in crate::log_store) fn observe_body(
        &mut self,
        decoded_bytes: usize,
    ) -> Result<(), LogStoreFailure> {
        self.add_decoded(decoded_bytes)
    }

    pub(in crate::log_store) fn observe_metadata(
        &mut self,
        decoded_bytes: usize,
    ) -> Result<(), LogStoreFailure> {
        self.add_decoded(decoded_bytes)
    }

    pub(in crate::log_store) fn observe_attribute(
        &mut self,
        namespace: AttributeNamespace,
        key_bytes: usize,
        occurrence_count: usize,
        occurrence_bytes: usize,
    ) -> Result<(), LogStoreFailure> {
        let index = match namespace {
            AttributeNamespace::Stream => 0,
            AttributeNamespace::Resource => 1,
            AttributeNamespace::InstrumentationScope => 2,
            AttributeNamespace::Record => 3,
        };
        let count = self
            .occurrences_by_namespace
            .get_mut(index)
            .ok_or_else(LogStoreFailure::invalid_input)?;
        *count = count
            .checked_add(occurrence_count)
            .filter(|count| *count <= self.maximum_occurrences)
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        self.add_decoded(key_bytes)?;
        self.add_decoded(occurrence_bytes)
    }

    fn add_decoded(&mut self, bytes: usize) -> Result<(), LogStoreFailure> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(bytes)
            .filter(|decoded| *decoded <= self.decoded_limit)
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        Ok(())
    }
}
