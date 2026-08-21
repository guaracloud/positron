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
    decode_mode(input, limits, version, DecodeMode::Build)?
        .ok_or_else(LogStoreFailure::malformed_block)
}

pub(super) fn validate(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
) -> Result<(), LogStoreFailure> {
    if decode_mode(input, limits, version, DecodeMode::ValidateOnly)?.is_some() {
        return Err(LogStoreFailure::malformed_block());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DecodeMode {
    Build,
    ValidateOnly,
}

fn decode_mode(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    mode: DecodeMode,
) -> Result<Option<DecodedRecord>, LogStoreFailure> {
    let event_time = decode_event_time(input)?;
    let observed_time = match input.u8()? {
        0 => None,
        1 => Some(decode_observed_time(input)?),
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let profile = value_profile();
    let mut validation =
        NativeRecordValidator::new(profile).map_err(|_| LogStoreFailure::malformed_block())?;
    let metadata = decode_metadata(input, limits, version, mode, &mut validation)?;
    let ingest_time = UnixNanoseconds::new(input.i64()?);
    let body = decode_body(input, limits, version, mode, profile, &mut validation)?;
    let attributes = decode_attributes(input, limits, version, mode, profile, &mut validation)?;
    let policy = decode_policy(input, mode)?;
    if matches!(mode, DecodeMode::ValidateOnly) {
        return Ok(None);
    }
    let record = LogRecord::checked_native(
        profile,
        event_time,
        observed_time,
        body,
        attributes.ok_or_else(LogStoreFailure::malformed_block)?,
        metadata.ok_or_else(LogStoreFailure::malformed_block)?,
        policy.ok_or_else(LogStoreFailure::malformed_block)?,
    )
    .map_err(|_| LogStoreFailure::malformed_block())?;
    Ok(Some(DecodedRecord {
        record,
        ingest_time,
    }))
}

fn decode_metadata(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    mode: DecodeMode,
    validation: &mut NativeRecordValidator,
) -> Result<Option<LogMetadata>, LogStoreFailure> {
    match (version, mode) {
        (LEGACY_VERSION, DecodeMode::Build) => Ok(Some(LogMetadata::empty())),
        (LEGACY_VERSION, DecodeMode::ValidateOnly) => {
            validation
                .observe_metadata(0)
                .map_err(|_| LogStoreFailure::malformed_block())?;
            Ok(None)
        },
        (_, DecodeMode::Build) => metadata::decode(input, limits).map(Some),
        (_, DecodeMode::ValidateOnly) => {
            let decoded_bytes = metadata::validate(input, limits)?;
            validation
                .observe_metadata(decoded_bytes)
                .map_err(|_| LogStoreFailure::malformed_block())?;
            Ok(None)
        },
    }
}

fn decode_body(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    mode: DecodeMode,
    profile: positron_domain::value::ValueLimitProfile,
    validation: &mut NativeRecordValidator,
) -> Result<Option<positron_domain::value::ValidatedAttributeValue>, LogStoreFailure> {
    match (input.u8()?, mode) {
        (0, _) => {
            validation
                .observe_body(0)
                .map_err(|_| LogStoreFailure::malformed_block())?;
            Ok(None)
        },
        (1, DecodeMode::Build) => value::decode(
            input,
            limits.nesting_depth,
            limits.body_bytes,
            limits,
            version,
        )?
        .validate_log_body(profile)
        .map(Some)
        .map_err(|_| LogStoreFailure::malformed_block()),
        (1, DecodeMode::ValidateOnly) => {
            let summary = value::validate(input, limits.nesting_depth, limits.body_bytes, limits)?;
            validation
                .observe_body(summary.decoded_bytes())
                .map_err(|_| LogStoreFailure::malformed_block())?;
            Ok(None)
        },
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

fn decode_attributes(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    mode: DecodeMode,
    profile: positron_domain::value::ValueLimitProfile,
    validation: &mut NativeRecordValidator,
) -> Result<Option<Vec<StoredLogAttribute>>, LogStoreFailure> {
    let count = input.count(limits.attribute_groups)?;
    let mut attributes = match mode {
        DecodeMode::Build => Some(bounded_vec(count)?),
        DecodeMode::ValidateOnly => None,
    };
    for _ in 0..count {
        decode_attribute(
            input,
            limits,
            version,
            mode,
            profile,
            validation,
            &mut attributes,
        )?;
    }
    Ok(attributes)
}

#[allow(clippy::too_many_arguments)]
fn decode_attribute(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
    mode: DecodeMode,
    profile: positron_domain::value::ValueLimitProfile,
    validation: &mut NativeRecordValidator,
    attributes: &mut Option<Vec<StoredLogAttribute>>,
) -> Result<(), LogStoreFailure> {
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
    let mut occurrences = match mode {
        DecodeMode::Build => Some(bounded_vec(count)?),
        DecodeMode::ValidateOnly => None,
    };
    let mut occurrence_bytes = 0_usize;
    for _ in 0..count {
        match &mut occurrences {
            Some(values) => values.push(value::decode(
                input,
                limits.nesting_depth,
                limits.value_bytes,
                limits,
                version,
            )?),
            None => {
                let summary =
                    value::validate(input, limits.nesting_depth, limits.value_bytes, limits)?;
                occurrence_bytes = occurrence_bytes
                    .checked_add(summary.decoded_bytes())
                    .ok_or_else(LogStoreFailure::malformed_block)?;
            },
        }
    }
    if let Some(values) = occurrences {
        let occurrences = AttributeOccurrenceSetCandidate::new(namespace, try_string(key)?, values)
            .validate(profile)
            .map_err(|_| LogStoreFailure::malformed_block())?;
        let attribute = match representation {
            AttributeRepresentation::Generic => StoredLogAttribute::generic(occurrences),
            AttributeRepresentation::SchemaOverflow => {
                StoredLogAttribute::schema_overflow(occurrences)
            },
        };
        attributes
            .as_mut()
            .ok_or_else(LogStoreFailure::malformed_block)?
            .push(attribute);
    } else {
        validation
            .observe_attribute(namespace, key.len(), count, occurrence_bytes)
            .map_err(|_| LogStoreFailure::malformed_block())?;
    }
    Ok(())
}

fn decode_policy(
    input: &mut Input<'_>,
    mode: DecodeMode,
) -> Result<Option<PolicyProvenance>, LogStoreFailure> {
    let generation = input.u64()?;
    let digest = input.array()?;
    let count = input.count(64)?;
    let mut rule_slices = [""; 64];
    for index in 0..count {
        *rule_slices
            .get_mut(index)
            .ok_or_else(LogStoreFailure::malformed_block)? = input.string_slice(256)?;
    }
    let rules = rule_slices
        .get(..count)
        .ok_or_else(LogStoreFailure::malformed_block)?;
    PolicyProvenance::validate_parts(generation, digest, rules.iter().copied())
        .map_err(|_| LogStoreFailure::malformed_block())?;
    if matches!(mode, DecodeMode::ValidateOnly) {
        return Ok(None);
    }
    let mut built = bounded_vec(count)?;
    for rule in rules {
        built.push(try_string(rule)?);
    }
    PolicyProvenance::new(generation, digest, built)
        .map(Some)
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

fn decode_quality(tag: u8) -> Result<SourceTimeQuality, LogStoreFailure> {
    match tag {
        1 => Ok(SourceTimeQuality::Usable),
        2 => Ok(SourceTimeQuality::Missing),
        3 => Ok(SourceTimeQuality::Zero),
        4 => Ok(SourceTimeQuality::Outlier),
        5 => Ok(SourceTimeQuality::Contradictory),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

fn decode_namespace(tag: u8, version: u16) -> Result<AttributeNamespace, LogStoreFailure> {
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
