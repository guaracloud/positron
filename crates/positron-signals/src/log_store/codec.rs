use positron_domain::identity::TenantId;
use positron_domain::time::{EventTime, ObservedTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{AttributeNamespace, AttributeOccurrenceSetCandidate};

use super::types::{
    AttributeRepresentation, LogRecord, StoredLogAttribute, StoredLogRecord, value_profile,
};
use super::{LogStoreFailure, PolicyProvenance};
use positron_kernel::LedgerSnapshot;

const MAGIC: &[u8; 8] = b"PLOGBL01";
const LEGACY_VERSION: u16 = 1;
const METADATA_VERSION: u16 = 2;
const VERSION: u16 = 3;
#[cfg(fuzzing)]
mod fuzz;
mod limits;
mod metadata;
mod primitives;
mod size;
mod value;
#[cfg(fuzzing)]
pub(super) use fuzz::fuzz_decode_block;
use limits::CodecLimits;
use primitives::{Input, put_bytes, put_count, put_i32, put_u16, put_u32};
pub(super) use size::encoded_block_length;

pub(super) fn encode_block(
    tenant: TenantId,
    records: &[StoredLogRecord],
    encoded_bytes: usize,
) -> Result<Vec<u8>, LogStoreFailure> {
    let limits = CodecLimits::release_1()?;
    if records.is_empty() || records.len() > limits.records {
        return Err(LogStoreFailure::limit_exceeded());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(encoded_bytes)
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    output.extend_from_slice(MAGIC);
    put_u16(&mut output, VERSION);
    output.extend_from_slice(&tenant.to_bytes());
    put_count(&mut output, records.len())?;
    for record in records {
        encode_record(&mut output, record, limits.nesting_depth)?;
    }
    if output.len() != encoded_bytes {
        return Err(LogStoreFailure::invalid_input());
    }
    Ok(output)
}

fn encode_record(
    output: &mut Vec<u8>,
    record: &StoredLogRecord,
    maximum_nesting_depth: u8,
) -> Result<(), LogStoreFailure> {
    encode_event_time(output, record.event_time());
    if let Some(observed) = record.observed_time() {
        output.push(1);
        encode_observed_time(output, observed);
    } else {
        output.push(0);
    }
    metadata::encode(output, record.record().metadata())?;
    output.extend_from_slice(&record.ingest_time().instant().value().to_be_bytes());
    if let Some(body) = record.body() {
        output.push(1);
        value::encode(output, body, maximum_nesting_depth)?;
    } else {
        output.push(0);
    }
    put_count(output, record.attributes().len())?;
    for attribute in record.attributes() {
        output.push(match attribute.representation() {
            AttributeRepresentation::Generic => 1,
            AttributeRepresentation::SchemaOverflow => 2,
        });
        let occurrences = attribute.occurrences();
        output.push(namespace_tag(occurrences.namespace()));
        put_bytes(output, occurrences.key().as_bytes())?;
        put_count(output, occurrences.len())?;
        for index in 0..occurrences.len() {
            let occurrence = occurrences
                .occurrence(index)
                .ok_or_else(LogStoreFailure::invalid_input)?;
            value::encode(output, occurrence, maximum_nesting_depth)?;
        }
    }
    let policy = record.policy_provenance();
    output.extend_from_slice(&policy.generation().to_be_bytes());
    output.extend_from_slice(&policy.digest());
    put_count(output, policy.applied_rules().len())?;
    for rule in policy.applied_rules() {
        put_bytes(output, rule.as_bytes())?;
    }
    Ok(())
}

fn encode_event_time(output: &mut Vec<u8>, time: EventTime) {
    output.push(quality_tag(time.quality()));
    if let Some(instant) = time.instant() {
        output.extend_from_slice(&instant.value().to_be_bytes());
    }
}

fn encode_observed_time(output: &mut Vec<u8>, time: ObservedTime) {
    output.push(quality_tag(time.quality()));
    output.extend_from_slice(
        &time
            .instant()
            .map_or(0, UnixNanoseconds::value)
            .to_be_bytes(),
    );
}

pub(super) fn decode_block(
    expected_tenant: TenantId,
    snapshot: &LedgerSnapshot<'_>,
    bytes: &[u8],
    limit: usize,
) -> Result<DecodedBlock, LogStoreFailure> {
    let mut input = Input::new(bytes);
    if input.take(MAGIC.len())? != MAGIC {
        return Err(LogStoreFailure::malformed_block());
    }
    let version = input.u16()?;
    if !matches!(version, LEGACY_VERSION | METADATA_VERSION | VERSION) {
        return Err(LogStoreFailure::malformed_block());
    }
    let tenant: [u8; 16] = input
        .take(16)?
        .try_into()
        .map_err(|_| LogStoreFailure::malformed_block())?;
    if tenant != expected_tenant.to_bytes() {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let limits = CodecLimits::release_1()?;
    let count = input.count(limits.records)?;
    if count == 0 {
        return Err(LogStoreFailure::malformed_block());
    }
    let retained_count = count.min(limit);
    let mut records = bounded_vec(retained_count)?;
    for index in 0..count {
        let decoded = decode_record(&mut input, limits, version)?;
        if index < retained_count {
            records.push(decoded.into_stored(snapshot));
        }
    }
    let truncated = retained_count < count;
    if !input.is_empty() {
        return Err(LogStoreFailure::malformed_block());
    }
    Ok(DecodedBlock { records, truncated })
}

pub(super) struct DecodedBlock {
    pub(super) records: Vec<StoredLogRecord>,
    pub(super) truncated: bool,
}

struct DecodedRecord {
    record: LogRecord,
    ingest_time: UnixNanoseconds,
}

impl DecodedRecord {
    fn into_stored(self, snapshot: &LedgerSnapshot<'_>) -> StoredLogRecord {
        StoredLogRecord::new(
            self.record,
            snapshot.reconstruct_ingest_time(self.ingest_time),
        )
    }
}

fn decode_record(
    input: &mut Input<'_>,
    limits: CodecLimits,
    version: u16,
) -> Result<DecodedRecord, LogStoreFailure> {
    let event_time = decode_event_time(input)?;
    let observed_time = match input.u8()? {
        0 => None,
        1 => Some(decode_observed_time(input)?),
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let metadata = if version == LEGACY_VERSION {
        super::LogMetadata::empty()
    } else {
        metadata::decode(input, limits)?
    };
    let ingest_time = UnixNanoseconds::new(input.i64()?);
    let profile = value_profile();
    let body = match input.u8()? {
        0 => None,
        1 => Some(
            value::decode(
                input,
                limits.nesting_depth,
                limits.body_bytes,
                limits,
                version,
            )?
            .validate_log_body(profile)
            .map_err(|_| LogStoreFailure::malformed_block())?,
        ),
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let attribute_count = input.count(limits.attribute_groups)?;
    let mut attributes = bounded_vec(attribute_count)?;
    for _ in 0..attribute_count {
        let representation = match input.u8()? {
            1 => AttributeRepresentation::Generic,
            2 => AttributeRepresentation::SchemaOverflow,
            _ => return Err(LogStoreFailure::malformed_block()),
        };
        let namespace = decode_namespace(input.u8()?, version)?;
        let key = input.string(limits.key_bytes)?;
        let occurrence_count = input.count(limits.occurrences)?;
        if occurrence_count == 0 {
            return Err(LogStoreFailure::malformed_block());
        }
        let mut occurrences = bounded_vec(occurrence_count)?;
        for _ in 0..occurrence_count {
            occurrences.push(value::decode(
                input,
                limits.nesting_depth,
                limits.value_bytes,
                limits,
                version,
            )?);
        }
        let occurrences = AttributeOccurrenceSetCandidate::new(namespace, key, occurrences)
            .validate(profile)
            .map_err(|_| LogStoreFailure::malformed_block())?;
        attributes.push(match representation {
            AttributeRepresentation::Generic => StoredLogAttribute::generic(occurrences),
            AttributeRepresentation::SchemaOverflow => {
                StoredLogAttribute::schema_overflow(occurrences)
            },
        });
    }
    let generation = input.u64()?;
    let digest = input.array()?;
    let rule_count = input.count(64)?;
    let mut rules = bounded_vec(rule_count)?;
    for _ in 0..rule_count {
        rules.push(input.string(256)?);
    }
    let policy = PolicyProvenance::new(generation, digest, rules)
        .map_err(|_| LogStoreFailure::malformed_block())?;
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

pub(super) fn bounded_vec<T>(count: usize) -> Result<Vec<T>, LogStoreFailure> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    Ok(values)
}

fn quality_tag(quality: SourceTimeQuality) -> u8 {
    match quality {
        SourceTimeQuality::Usable => 1,
        SourceTimeQuality::Missing => 2,
        SourceTimeQuality::Zero => 3,
        SourceTimeQuality::Outlier => 4,
        SourceTimeQuality::Contradictory => 5,
    }
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

fn namespace_tag(namespace: AttributeNamespace) -> u8 {
    match namespace {
        AttributeNamespace::Resource => 1,
        AttributeNamespace::InstrumentationScope => 2,
        AttributeNamespace::Record => 3,
        AttributeNamespace::Stream => 4,
    }
}

fn decode_namespace(tag: u8, version: u16) -> Result<AttributeNamespace, LogStoreFailure> {
    match (tag, version) {
        (1, _) => Ok(AttributeNamespace::Resource),
        (2, _) => Ok(AttributeNamespace::InstrumentationScope),
        (3, _) => Ok(AttributeNamespace::Record),
        (4, METADATA_VERSION | VERSION) => Ok(AttributeNamespace::Stream),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}
