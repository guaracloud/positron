use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{AttributeNamespace, AttributeOccurrenceSetCandidate};
use positron_kernel::LedgerSnapshot;

use super::{CodecLimits, Input, LEGACY_VERSION, METADATA_VERSION, bounded_vec, metadata, value};
use crate::log_store::types::{
    AttributeRepresentation, LogRecord, NativeRecordValidator, StoredLogAttribute, StoredLogRecord,
    value_profile,
};
use crate::log_store::{LogMetadata, LogStoreFailure, PolicyProvenance};

pub(super) struct DecodedRecord {
    record: LogRecord,
    ingest_time: UnixNanoseconds,
}

impl DecodedRecord {
    pub(super) fn into_stored(self, snapshot: &LedgerSnapshot<'_>) -> StoredLogRecord {
        StoredLogRecord::new(
            self.record,
            snapshot.reconstruct_ingest_time(self.ingest_time),
        )
    }
}

pub(super) fn decode(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
) -> Result<DecodedRecord, LogStoreFailure> {
    input.observe_component()?;
    let event_time = decode_event_time(input)?;
    let observed_time = match input.u8()? {
        0 => None,
        1 => Some(decode_observed_time(input)?),
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let profile = value_profile();
    let mut validation =
        NativeRecordValidator::new(profile).map_err(|_| LogStoreFailure::malformed_block())?;
    let metadata = decode_metadata(input, limits, version, &mut validation)?;
    let ingest_time = UnixNanoseconds::new(input.i64()?);
    let body = decode_body(input, limits, version, profile, &mut validation)?;
    let attributes = decode_attributes(input, limits, version, profile)?;
    let policy = decode_policy(input)?;
    let record = LogRecord::checked_native(
        profile,
        event_time,
        observed_time,
        body,
        attributes,
        metadata,
        policy,
    )
    .map_err(|_| LogStoreFailure::malformed_block())?;
    Ok(DecodedRecord {
        record,
        ingest_time,
    })
}

/// Validates only the authenticated record framing and bounded value
/// structure. This is used for records beyond a hard decode limit: they must
/// still be consumed and rejected when malformed, but must not be built into
/// semantic record values or charged as decoded records.
pub(super) fn validate_structure(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
) -> Result<(), LogStoreFailure> {
    validate_structure_with_ingest_time(input, limits, version).map(|_| ())
}

fn validate_structure_with_ingest_time(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
) -> Result<UnixNanoseconds, LogStoreFailure> {
    input.observe_component()?;
    decode_event_time(input)?;
    match input.u8()? {
        0 => {},
        1 => {
            decode_observed_time(input)?;
        },
        _ => return Err(LogStoreFailure::malformed_block()),
    }
    let profile = value_profile();
    let mut validation =
        NativeRecordValidator::new(profile).map_err(|_| LogStoreFailure::malformed_block())?;
    if version != LEGACY_VERSION {
        let decoded_bytes = metadata::validate(input, limits)?;
        validation
            .observe_metadata(decoded_bytes)
            .map_err(|_| LogStoreFailure::malformed_block())?;
    } else {
        validation
            .observe_metadata(0)
            .map_err(|_| LogStoreFailure::malformed_block())?;
    }
    let ingest_time = UnixNanoseconds::new(input.i64()?);
    match input.u8()? {
        0 => {},
        1 => {
            let summary = value::validate(input, limits.nesting_depth, limits.body_bytes, limits)?;
            validation
                .observe_body(summary.decoded_bytes())
                .map_err(|_| LogStoreFailure::malformed_block())?;
        },
        _ => return Err(LogStoreFailure::malformed_block()),
    }
    let attributes = input.count(limits.attribute_groups)?;
    for _ in 0..attributes {
        input.observe_component()?;
        let representation = input.u8()?;
        if !matches!(representation, 1 | 2) {
            return Err(LogStoreFailure::malformed_block());
        }
        let namespace = decode_namespace(input.u8()?, version)?;
        let key = input.string_slice(limits.key_bytes)?;
        if key.is_empty() {
            return Err(LogStoreFailure::malformed_block());
        }
        let occurrences = input.count(limits.occurrences)?;
        if occurrences == 0 {
            return Err(LogStoreFailure::malformed_block());
        }
        let mut occurrence_bytes = 0_usize;
        for _ in 0..occurrences {
            let summary = value::validate(input, limits.nesting_depth, limits.value_bytes, limits)?;
            occurrence_bytes = occurrence_bytes
                .checked_add(summary.decoded_bytes())
                .ok_or_else(LogStoreFailure::malformed_block)?;
        }
        validation
            .observe_attribute(namespace, key.len(), occurrences, occurrence_bytes)
            .map_err(|_| LogStoreFailure::malformed_block())?;
    }
    validate_policy(input)?;
    Ok(ingest_time)
}

fn decode_metadata(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    validation: &mut NativeRecordValidator,
) -> Result<LogMetadata, LogStoreFailure> {
    if version == LEGACY_VERSION {
        validation
            .observe_metadata(0)
            .map_err(|_| LogStoreFailure::malformed_block())?;
        Ok(LogMetadata::empty())
    } else {
        metadata::decode(input, limits)
    }
}

fn decode_body(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    profile: positron_domain::value::ValueLimitProfile,
    validation: &mut NativeRecordValidator,
) -> Result<Option<positron_domain::value::ValidatedAttributeValue>, LogStoreFailure> {
    match input.u8()? {
        0 => {
            validation
                .observe_body(0)
                .map_err(|_| LogStoreFailure::malformed_block())?;
            Ok(None)
        },
        1 => value::decode(
            input,
            limits.nesting_depth,
            limits.body_bytes,
            limits,
            version,
        )?
        .validate_log_body(profile)
        .map(Some)
        .map_err(|_| LogStoreFailure::malformed_block()),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

fn decode_attributes(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    profile: positron_domain::value::ValueLimitProfile,
) -> Result<Vec<StoredLogAttribute>, LogStoreFailure> {
    let count = input.count(limits.attribute_groups)?;
    let mut attributes = bounded_vec(count)?;
    for _ in 0..count {
        decode_attribute(input, limits, version, profile, &mut attributes)?;
    }
    Ok(attributes)
}

#[allow(clippy::too_many_arguments)]
fn decode_attribute(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    profile: positron_domain::value::ValueLimitProfile,
    attributes: &mut Vec<StoredLogAttribute>,
) -> Result<(), LogStoreFailure> {
    input.observe_component()?;
    let representation = match input.u8()? {
        1 => AttributeRepresentation::Generic,
        2 => AttributeRepresentation::SchemaOverflow,
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let namespace = decode_namespace(input.u8()?, version)?;
    let key = input.string_slice(limits.key_bytes)?;
    if key.is_empty() {
        return Err(LogStoreFailure::malformed_block());
    }
    let count = input.count(limits.occurrences)?;
    if count == 0 {
        return Err(LogStoreFailure::malformed_block());
    }
    let mut occurrences = bounded_vec(count)?;
    for _ in 0..count {
        occurrences.push(value::decode(
            input,
            limits.nesting_depth,
            limits.value_bytes,
            limits,
            version,
        )?);
    }
    let occurrences =
        AttributeOccurrenceSetCandidate::new(namespace, try_string(key)?, occurrences)
            .validate(profile)
            .map_err(|_| LogStoreFailure::malformed_block())?;
    let attribute = match representation {
        AttributeRepresentation::Generic => StoredLogAttribute::generic(occurrences),
        AttributeRepresentation::SchemaOverflow => StoredLogAttribute::schema_overflow(occurrences),
    };
    attributes.push(attribute);
    Ok(())
}

fn decode_policy(input: &mut Input<'_>) -> Result<PolicyProvenance, LogStoreFailure> {
    let generation = input.u64()?;
    let digest = input.array()?;
    let count = input.count(PolicyProvenance::MAX_APPLIED_RULES)?;
    let mut rule_slices = [""; PolicyProvenance::MAX_APPLIED_RULES];
    for index in 0..count {
        input.observe_component()?;
        *rule_slices
            .get_mut(index)
            .ok_or_else(LogStoreFailure::malformed_block)? =
            input.string_slice(PolicyProvenance::MAX_RULE_ID_BYTES)?;
    }
    let rules = rule_slices
        .get(..count)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    PolicyProvenance::validate_parts(generation, digest, rules.iter().copied())
        .map_err(|_| LogStoreFailure::malformed_block())?;
    let mut built = bounded_vec(count)?;
    for rule in rules {
        built.push(try_string(rule)?);
    }
    PolicyProvenance::new(generation, digest, built).map_err(|_| LogStoreFailure::malformed_block())
}

fn validate_policy(input: &mut Input<'_>) -> Result<(), LogStoreFailure> {
    let generation = input.u64()?;
    let digest = input.array()?;
    let count = input.count(PolicyProvenance::MAX_APPLIED_RULES)?;
    let mut rule_slices = [""; PolicyProvenance::MAX_APPLIED_RULES];
    for index in 0..count {
        input.observe_component()?;
        *rule_slices
            .get_mut(index)
            .ok_or_else(LogStoreFailure::malformed_block)? =
            input.string_slice(PolicyProvenance::MAX_RULE_ID_BYTES)?;
    }
    let rules = rule_slices
        .get(..count)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    PolicyProvenance::validate_parts(generation, digest, rules.iter().copied())
        .map_err(|_| LogStoreFailure::malformed_block())
}

fn decode_event_time(input: &mut Input<'_>) -> Result<EventTime, LogStoreFailure> {
    let quality = decode_quality(input.u8()?)?;
    if quality == SourceTimeQuality::Missing {
        return Ok(EventTime::missing());
    }
    EventTime::received(UnixNanoseconds::new(input.i64()?), quality)
        .map_err(|_| LogStoreFailure::malformed_block())
}

fn decode_observed_time(input: &mut Input<'_>) -> Result<ObservedTime, LogStoreFailure> {
    let quality = decode_quality(input.u8()?)?;
    ObservedTime::received(UnixNanoseconds::new(input.i64()?), quality)
        .map_err(|_| LogStoreFailure::malformed_block())
}

pub(super) fn decode_quality(tag: u8) -> Result<SourceTimeQuality, LogStoreFailure> {
    match tag {
        1 => Ok(SourceTimeQuality::Usable),
        2 => Ok(SourceTimeQuality::Missing),
        3 => Ok(SourceTimeQuality::Zero),
        4 => Ok(SourceTimeQuality::Outlier),
        5 => Ok(SourceTimeQuality::Contradictory),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

pub(super) fn decode_namespace(
    tag: u8,
    version: u16,
) -> Result<AttributeNamespace, LogStoreFailure> {
    match (tag, version) {
        (1, _) => Ok(AttributeNamespace::Resource),
        (2, _) => Ok(AttributeNamespace::InstrumentationScope),
        (3, _) => Ok(AttributeNamespace::Record),
        (4, METADATA_VERSION) => Ok(AttributeNamespace::Stream),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

fn try_string(source: &str) -> Result<String, LogStoreFailure> {
    let mut value = String::new();
    value
        .try_reserve_exact(source.len())
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    value.push_str(source);
    Ok(value)
}
