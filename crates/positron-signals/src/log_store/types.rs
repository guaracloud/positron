use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate,
    CandidateAttributeValue, ValidatedAttributeValue, ValueLimitProfile,
};
use positron_kernel::{IngestTime, PreparedStoreBlock};

use super::{LogMetadata, PolicyProvenance, failure::LogStoreFailure};

mod evaluated;

/// The M1 physical dynamic-attribute representation carried by a Log Block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeRepresentation {
    /// The ordinary typed generic representation.
    Generic,
    /// Typed Schema Overflow that does not grow catalog or index state.
    SchemaOverflow,
}

/// One checked occurrence set plus its reversible physical representation.
#[derive(Clone, Debug)]
pub struct StoredLogAttribute {
    representation: AttributeRepresentation,
    occurrences: AttributeOccurrenceSet,
}

impl PartialEq for StoredLogAttribute {
    fn eq(&self, other: &Self) -> bool {
        self.occurrences == other.occurrences
    }
}

impl Eq for StoredLogAttribute {}

impl StoredLogAttribute {
    #[must_use]
    pub const fn generic(occurrences: AttributeOccurrenceSet) -> Self {
        Self {
            representation: AttributeRepresentation::Generic,
            occurrences,
        }
    }

    #[must_use]
    pub const fn schema_overflow(occurrences: AttributeOccurrenceSet) -> Self {
        Self {
            representation: AttributeRepresentation::SchemaOverflow,
            occurrences,
        }
    }

    #[must_use]
    pub const fn representation(&self) -> AttributeRepresentation {
        self.representation
    }

    #[must_use]
    pub const fn occurrences(&self) -> &AttributeOccurrenceSet {
        &self.occurrences
    }

    pub(super) const fn set_representation(&mut self, representation: AttributeRepresentation) {
        self.representation = representation;
    }
}

/// The checked minimal native log record needed by the M1 vertical slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRecord {
    event_time: EventTime,
    observed_time: Option<ObservedTime>,
    body: Option<ValidatedAttributeValue>,
    attributes: Vec<StoredLogAttribute>,
    metadata: LogMetadata,
    policy: PolicyProvenance,
}

impl LogRecord {
    /// Applies the Log Store's authoritative semantic Value Limits to a
    /// receiver-native candidate after Ingest Policy evaluation.
    #[cfg(test)]
    pub(crate) fn checked_receiver_candidate(
        profile: ValueLimitProfile,
        event_time_unix_nanos: Option<i64>,
        observed_time_unix_nanos: Option<i64>,
        body: Option<CandidateAttributeValue>,
        attributes: Vec<AttributeOccurrenceSetCandidate>,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        Self::checked_receiver_candidate_with_metadata(
            profile,
            event_time_unix_nanos,
            observed_time_unix_nanos,
            body,
            attributes,
            LogMetadata::empty(),
            policy,
        )
    }

    /// Applies semantic limits while preserving receiver-native intrinsic metadata.
    pub(crate) fn checked_receiver_candidate_with_metadata(
        profile: ValueLimitProfile,
        event_time_unix_nanos: Option<i64>,
        observed_time_unix_nanos: Option<i64>,
        body: Option<CandidateAttributeValue>,
        attributes: Vec<AttributeOccurrenceSetCandidate>,
        metadata: LogMetadata,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        let event_time = checked_event_time(event_time_unix_nanos)?;
        let observed_time = observed_time_unix_nanos
            .map(|value| {
                let quality = if value == 0 {
                    SourceTimeQuality::Zero
                } else {
                    SourceTimeQuality::Usable
                };
                ObservedTime::received(UnixNanoseconds::new(value), quality)
                    .map_err(|_| LogStoreFailure::invalid_input())
            })
            .transpose()?;
        let body = body
            .map(|body| {
                body.validate_log_body(profile)
                    .map_err(LogStoreFailure::domain)
            })
            .transpose()?;
        let attributes = attributes
            .into_iter()
            .map(|attribute| {
                attribute
                    .validate(profile)
                    .map(StoredLogAttribute::generic)
                    .map_err(LogStoreFailure::domain)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::checked_native(
            profile,
            event_time,
            observed_time,
            body,
            attributes,
            metadata,
            policy,
        )
    }

    #[cfg(test)]
    pub(crate) fn checked_minimal(
        event_time_unix_nanos: Option<i64>,
        body: Option<String>,
        attributes: Vec<(&str, &str, &str)>,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        let profile = value_profile();
        let event_time = checked_event_time(event_time_unix_nanos)?;
        let body = body
            .map(|body| {
                CandidateAttributeValue::string(body)
                    .validate_log_body(profile)
                    .map_err(LogStoreFailure::domain)
            })
            .transpose()?;
        let mut checked: Vec<StoredLogAttribute> = Vec::new();
        for (namespace, key, value) in attributes {
            let namespace = match namespace {
                "resource" => AttributeNamespace::Resource,
                "stream" => AttributeNamespace::Stream,
                "scope" | "instrumentation-scope" => AttributeNamespace::InstrumentationScope,
                "record" => AttributeNamespace::Record,
                _ => return Err(LogStoreFailure::invalid_input()),
            };
            checked.push(StoredLogAttribute::generic(
                AttributeOccurrenceSetCandidate::new(
                    namespace,
                    key.to_owned(),
                    vec![CandidateAttributeValue::string(value.to_owned())],
                )
                .validate(profile)
                .map_err(LogStoreFailure::domain)?,
            ));
        }
        Self::checked_native(
            profile,
            event_time,
            None,
            body,
            checked,
            LogMetadata::empty(),
            policy,
        )
    }

    pub(super) fn checked_native(
        profile: ValueLimitProfile,
        event_time: EventTime,
        observed_time: Option<ObservedTime>,
        body: Option<ValidatedAttributeValue>,
        attributes: Vec<StoredLogAttribute>,
        metadata: LogMetadata,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        let maximum = usize::try_from(
            profile
                .effective_limits()
                .dynamic_value()
                .attributes_per_namespace()
                .value(),
        )
        .map_err(|_| LogStoreFailure::limit_exceeded())?;
        let mut occurrences_by_namespace = [0_usize; 4];
        for attribute in &attributes {
            let index = match attribute.occurrences().namespace() {
                AttributeNamespace::Stream => 0,
                AttributeNamespace::Resource => 1,
                AttributeNamespace::InstrumentationScope => 2,
                AttributeNamespace::Record => 3,
            };
            let count = occurrences_by_namespace
                .get_mut(index)
                .ok_or_else(LogStoreFailure::invalid_input)?;
            *count = count
                .checked_add(attribute.occurrences().len())
                .filter(|count| *count <= maximum)
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
        }
        let decoded_limit =
            usize::try_from(profile.effective_limits().record().decoded_bytes().value())
                .map_err(|_| LogStoreFailure::limit_exceeded())?;
        let mut decoded_bytes = body
            .as_ref()
            .map_or(Ok(0), ValidatedAttributeValue::decoded_size_bytes)
            .map_err(LogStoreFailure::domain)?;
        for attribute in &attributes {
            decoded_bytes = decoded_bytes
                .checked_add(attribute.occurrences().key().len())
                .ok_or_else(LogStoreFailure::limit_exceeded)?;
            for index in 0..attribute.occurrences().len() {
                let value = attribute
                    .occurrences()
                    .occurrence(index)
                    .ok_or_else(LogStoreFailure::invalid_input)?;
                decoded_bytes = decoded_bytes
                    .checked_add(
                        value
                            .decoded_size_bytes()
                            .map_err(LogStoreFailure::domain)?,
                    )
                    .filter(|bytes| *bytes <= decoded_limit)
                    .ok_or_else(LogStoreFailure::limit_exceeded)?;
            }
        }
        decoded_bytes = decoded_bytes
            .checked_add(
                metadata
                    .decoded_size_bytes()
                    .ok_or_else(LogStoreFailure::limit_exceeded)?,
            )
            .ok_or_else(LogStoreFailure::limit_exceeded)?;
        if decoded_bytes > decoded_limit {
            return Err(LogStoreFailure::limit_exceeded());
        }
        Ok(Self {
            event_time,
            observed_time,
            body,
            attributes,
            metadata,
            policy,
        })
    }

    #[must_use]
    pub const fn event_time(&self) -> EventTime {
        self.event_time
    }

    #[must_use]
    pub const fn observed_time(&self) -> Option<ObservedTime> {
        self.observed_time
    }

    #[must_use]
    pub const fn body(&self) -> Option<&ValidatedAttributeValue> {
        self.body.as_ref()
    }

    #[must_use]
    pub fn attributes(&self) -> &[StoredLogAttribute] {
        &self.attributes
    }

    pub(super) fn attributes_mut(&mut self) -> &mut [StoredLogAttribute] {
        &mut self.attributes
    }

    #[must_use]
    pub const fn metadata(&self) -> &LogMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn policy_provenance(&self) -> &PolicyProvenance {
        &self.policy
    }
}

fn checked_event_time(value: Option<i64>) -> Result<EventTime, LogStoreFailure> {
    match value {
        Some(0) => EventTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Zero),
        Some(value) => EventTime::received(UnixNanoseconds::new(value), SourceTimeQuality::Usable),
        None => Ok(EventTime::missing()),
    }
    .map_err(|_| LogStoreFailure::invalid_input())
}

/// One immutable accepted log after the kernel assigned Ingest Time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredLogRecord {
    record: LogRecord,
    ingest_time: IngestTime,
}

impl StoredLogRecord {
    pub(super) const fn new(record: LogRecord, ingest_time: IngestTime) -> Self {
        Self {
            record,
            ingest_time,
        }
    }

    #[must_use]
    pub const fn record(&self) -> &LogRecord {
        &self.record
    }

    #[must_use]
    pub const fn event_time(&self) -> EventTime {
        self.record.event_time()
    }

    #[must_use]
    pub const fn observed_time(&self) -> Option<ObservedTime> {
        self.record.observed_time()
    }

    #[must_use]
    pub const fn ingest_time(&self) -> IngestTime {
        self.ingest_time
    }

    #[must_use]
    pub const fn retention_time(&self) -> UnixNanoseconds {
        self.ingest_time.instant()
    }

    #[must_use]
    pub const fn body(&self) -> Option<&ValidatedAttributeValue> {
        self.record.body()
    }

    #[must_use]
    pub fn attributes(&self) -> &[StoredLogAttribute] {
        self.record.attributes()
    }

    #[must_use]
    pub const fn metadata(&self) -> &LogMetadata {
        self.record.metadata()
    }

    #[must_use]
    pub const fn policy_provenance(&self) -> &PolicyProvenance {
        self.record.policy_provenance()
    }
}

pub(super) const fn value_profile() -> ValueLimitProfile {
    ValueLimitProfile::release_1_system_maximum()
}

/// Opaque checked Log Store output accepted by the Storage Kernel ledger.
pub struct PreparedLogBlock<'capacity> {
    block: PreparedStoreBlock<'capacity>,
}

impl<'capacity> PreparedLogBlock<'capacity> {
    pub(super) const fn new(block: PreparedStoreBlock<'capacity>) -> Self {
        Self { block }
    }

    #[must_use]
    pub fn into_store_block(self) -> PreparedStoreBlock<'capacity> {
        self.block
    }
}
