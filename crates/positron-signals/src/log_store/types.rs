use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSet, AttributeOccurrenceSetCandidate, ByteLimit,
    CandidateAttributeValue, CollectionLimit, DynamicValueLimits, NestingLimit, RecordLimits,
    RequestLimits, ValidatedAttributeValue, ValueLimitProfile, ValueLimitProfileCandidate,
    ValueLimitSet,
};
use positron_kernel::{IngestTime, PreparedStoreBlock};

use super::failure::LogStoreFailure;

const MAX_POLICY_RULES: usize = 64;
const MAX_RULE_ID_BYTES: usize = 256;
const MAX_ATTRIBUTES: usize = 1_024;
const MAX_ATTRIBUTE_BYTES: usize = 65_536;
const MAX_BODY_BYTES: usize = 262_144;

/// Immutable evidence identifying the Ingest Policy applied before persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyProvenance {
    generation: u64,
    digest: [u8; 32],
    applied_rules: Vec<String>,
}

impl PolicyProvenance {
    pub fn new(
        generation: u64,
        digest: [u8; 32],
        applied_rules: Vec<String>,
    ) -> Result<Self, LogStoreFailure> {
        if generation == 0
            || digest.iter().all(|byte| *byte == 0)
            || applied_rules.len() > MAX_POLICY_RULES
            || applied_rules
                .iter()
                .any(|rule| rule.is_empty() || rule.len() > MAX_RULE_ID_BYTES)
        {
            return Err(LogStoreFailure::invalid_input());
        }
        Ok(Self {
            generation,
            digest,
            applied_rules,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn applied_rules(&self) -> &[String] {
        &self.applied_rules
    }
}

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
}

/// The checked minimal native log record needed by the M1 vertical slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRecord {
    event_time: EventTime,
    observed_time: Option<ObservedTime>,
    body: Option<ValidatedAttributeValue>,
    attributes: Vec<StoredLogAttribute>,
    policy: PolicyProvenance,
}

impl LogRecord {
    pub fn checked_minimal(
        event_time_unix_nanos: Option<i64>,
        body: Option<String>,
        attributes: Vec<(&str, &str, &str)>,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        let profile = value_profile()?;
        let event_time = match event_time_unix_nanos {
            Some(0) => EventTime::received(UnixNanoseconds::new(0), SourceTimeQuality::Zero),
            Some(value) => {
                EventTime::received(UnixNanoseconds::new(value), SourceTimeQuality::Usable)
            },
            None => Ok(EventTime::missing()),
        }
        .map_err(|_| LogStoreFailure::invalid_input())?;
        let body_profile = body_value_profile()?;
        let body = body
            .map(|body| validated_value(body_profile, CandidateAttributeValue::string(body)))
            .transpose()?;
        let mut checked: Vec<StoredLogAttribute> = Vec::new();
        for (namespace, key, value) in attributes {
            let namespace = match namespace {
                "resource" => AttributeNamespace::Resource,
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
                .map_err(|_| LogStoreFailure::limit_exceeded())?,
            ));
        }
        Self::checked_native(event_time, None, body, checked, policy)
    }

    pub fn checked_native(
        event_time: EventTime,
        observed_time: Option<ObservedTime>,
        body: Option<ValidatedAttributeValue>,
        attributes: Vec<StoredLogAttribute>,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(LogStoreFailure::limit_exceeded());
        }
        Ok(Self {
            event_time,
            observed_time,
            body,
            attributes,
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

    #[must_use]
    pub const fn policy_provenance(&self) -> &PolicyProvenance {
        &self.policy
    }
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
    pub const fn policy_provenance(&self) -> &PolicyProvenance {
        self.record.policy_provenance()
    }

    pub(super) fn from_decoded(
        event_time: EventTime,
        observed_time: Option<ObservedTime>,
        ingest_time: IngestTime,
        body: Option<ValidatedAttributeValue>,
        attributes: Vec<StoredLogAttribute>,
        policy: PolicyProvenance,
    ) -> Result<Self, LogStoreFailure> {
        let record = LogRecord::checked_native(event_time, observed_time, body, attributes, policy)
            .map_err(|_| LogStoreFailure::malformed_block())?;
        Ok(Self::new(record, ingest_time))
    }
}

pub(super) fn value_profile() -> Result<ValueLimitProfile, LogStoreFailure> {
    value_profile_with(MAX_ATTRIBUTE_BYTES as u32)
}

pub(super) fn body_value_profile() -> Result<ValueLimitProfile, LogStoreFailure> {
    value_profile_with(MAX_BODY_BYTES as u32)
}

fn value_profile_with(individual_value_bytes: u32) -> Result<ValueLimitProfile, LogStoreFailure> {
    let bytes = |value| ByteLimit::new(value).map_err(|_| LogStoreFailure::invalid_input());
    let entries = |value| CollectionLimit::new(value).map_err(|_| LogStoreFailure::invalid_input());
    let request = RequestLimits::new(
        bytes(1_048_576)?,
        bytes(1_048_576)?,
        entries(1_024)?,
        entries(4_096)?,
    );
    let record = RecordLimits::new(
        bytes(1_048_576)?,
        bytes(1_048_576)?,
        bytes(MAX_BODY_BYTES as u32)?,
    );
    let dynamic = DynamicValueLimits::new(
        bytes(individual_value_bytes)?,
        entries(MAX_ATTRIBUTES as u32)?,
        bytes(MAX_ATTRIBUTE_BYTES as u32)?,
        NestingLimit::new(16).map_err(|_| LogStoreFailure::invalid_input())?,
        entries(1_024)?,
        entries(1_024)?,
    );
    ValueLimitProfileCandidate::new(ValueLimitSet::new(request, record, dynamic), None)
        .validate()
        .map_err(|_| LogStoreFailure::invalid_input())
}

pub(super) fn validated_value(
    profile: ValueLimitProfile,
    candidate: CandidateAttributeValue,
) -> Result<ValidatedAttributeValue, LogStoreFailure> {
    let set = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "value".to_owned(),
        vec![candidate],
    )
    .validate(profile)
    .map_err(|_| LogStoreFailure::limit_exceeded())?;
    set.occurrence(0)
        .cloned()
        .ok_or_else(LogStoreFailure::invalid_input)
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
