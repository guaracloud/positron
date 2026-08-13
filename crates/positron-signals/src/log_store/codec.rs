use positron_domain::identity::TenantId;
use positron_domain::time::{
    EventTime, IngestTime, IngestTimeCandidate, ObservedTime, SourceTimeQuality, UnixNanoseconds,
};
use positron_domain::value::{AttributeNamespace, AttributeOccurrenceSetCandidate};

use super::LogStoreFailure;
use super::types::{
    AttributeRepresentation, LogRecord, PolicyProvenance, StoredLogAttribute, body_value_profile,
    validated_value, value_profile,
};

const MAGIC: &[u8; 8] = b"PLOGBL01";
const VERSION: u16 = 1;
const MAX_RECORDS: usize = 1_024;
const MAX_COLLECTION: usize = 1_024;
const MAX_NESTING: u8 = 16;

mod value;

pub(super) fn encode_block(
    tenant: TenantId,
    records: &[LogRecord],
) -> Result<Vec<u8>, LogStoreFailure> {
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err(LogStoreFailure::limit_exceeded());
    }
    let mut output = Vec::new();
    output
        .try_reserve(28)
        .map_err(|_| LogStoreFailure::resource_exhausted())?;
    output.extend_from_slice(MAGIC);
    put_u16(&mut output, VERSION);
    output.extend_from_slice(&tenant.to_bytes());
    put_count(&mut output, records.len())?;
    for record in records {
        encode_record(&mut output, record)?;
    }
    Ok(output)
}

fn encode_record(output: &mut Vec<u8>, record: &LogRecord) -> Result<(), LogStoreFailure> {
    encode_event_time(output, record.event_time());
    if let Some(observed) = record.observed_time() {
        output.push(1);
        encode_observed_time(output, observed);
    } else {
        output.push(0);
    }
    output.extend_from_slice(&record.ingest_time().instant().value().to_be_bytes());
    if let Some(body) = record.body() {
        output.push(1);
        value::encode(output, body, MAX_NESTING)?;
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
            value::encode(output, occurrence, MAX_NESTING)?;
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
    bytes: &[u8],
) -> Result<Vec<LogRecord>, LogStoreFailure> {
    let mut input = Input::new(bytes);
    if input.take(MAGIC.len())? != MAGIC || input.u16()? != VERSION {
        return Err(LogStoreFailure::malformed_block());
    }
    let tenant: [u8; 16] = input
        .take(16)?
        .try_into()
        .map_err(|_| LogStoreFailure::malformed_block())?;
    if tenant != expected_tenant.to_bytes() {
        return Err(LogStoreFailure::physical_scope_mismatch());
    }
    let count = input.count(MAX_RECORDS)?;
    if count == 0 {
        return Err(LogStoreFailure::malformed_block());
    }
    let mut records = bounded_vec(count)?;
    for _ in 0..count {
        records.push(decode_record(&mut input)?);
    }
    if !input.is_empty() {
        return Err(LogStoreFailure::malformed_block());
    }
    Ok(records)
}

fn decode_record(input: &mut Input<'_>) -> Result<LogRecord, LogStoreFailure> {
    let event_time = decode_event_time(input)?;
    let observed_time = match input.u8()? {
        0 => None,
        1 => Some(decode_observed_time(input)?),
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let ingest_time =
        IngestTime::assign(IngestTimeCandidate::new(UnixNanoseconds::new(input.i64()?)));
    let body_profile = body_value_profile()?;
    let body = match input.u8()? {
        0 => None,
        1 => Some(
            validated_value(body_profile, value::decode(input, MAX_NESTING)?)
                .map_err(|_| LogStoreFailure::malformed_block())?,
        ),
        _ => return Err(LogStoreFailure::malformed_block()),
    };
    let profile = value_profile()?;
    let attribute_count = input.count(MAX_COLLECTION)?;
    let mut attributes = bounded_vec(attribute_count)?;
    for _ in 0..attribute_count {
        let representation = match input.u8()? {
            1 => AttributeRepresentation::Generic,
            2 => AttributeRepresentation::SchemaOverflow,
            _ => return Err(LogStoreFailure::malformed_block()),
        };
        let namespace = decode_namespace(input.u8()?)?;
        let key = input.string(65_536)?;
        let occurrence_count = input.count(MAX_COLLECTION)?;
        if occurrence_count == 0 {
            return Err(LogStoreFailure::malformed_block());
        }
        let mut occurrences = bounded_vec(occurrence_count)?;
        for _ in 0..occurrence_count {
            occurrences.push(value::decode(input, MAX_NESTING)?);
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
    LogRecord::from_decoded(
        event_time,
        observed_time,
        ingest_time,
        body,
        attributes,
        policy,
    )
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
    }
}

fn decode_namespace(tag: u8) -> Result<AttributeNamespace, LogStoreFailure> {
    match tag {
        1 => Ok(AttributeNamespace::Resource),
        2 => Ok(AttributeNamespace::InstrumentationScope),
        3 => Ok(AttributeNamespace::Record),
        _ => Err(LogStoreFailure::malformed_block()),
    }
}

pub(super) fn put_count(output: &mut Vec<u8>, value: usize) -> Result<(), LogStoreFailure> {
    put_u16(
        output,
        u16::try_from(value).map_err(|_| LogStoreFailure::limit_exceeded())?,
    );
    Ok(())
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), LogStoreFailure> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| LogStoreFailure::limit_exceeded())?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

pub(super) struct Input<'a> {
    remaining: &'a [u8],
}

impl<'a> Input<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], LogStoreFailure> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(count)
            .ok_or_else(LogStoreFailure::malformed_block)?;
        self.remaining = remaining;
        Ok(value)
    }

    pub(super) fn u8(&mut self) -> Result<u8, LogStoreFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(LogStoreFailure::malformed_block)
    }

    fn u16(&mut self) -> Result<u16, LogStoreFailure> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, LogStoreFailure> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, LogStoreFailure> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn i64(&mut self) -> Result<i64, LogStoreFailure> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], LogStoreFailure> {
        self.take(N)?
            .try_into()
            .map_err(|_| LogStoreFailure::malformed_block())
    }

    pub(super) fn count(&mut self, maximum: usize) -> Result<usize, LogStoreFailure> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            return Err(LogStoreFailure::malformed_block());
        }
        Ok(count)
    }

    pub(super) fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, LogStoreFailure> {
        let count = usize::try_from(self.u32()?).map_err(|_| LogStoreFailure::malformed_block())?;
        if count > maximum {
            return Err(LogStoreFailure::malformed_block());
        }
        let source = self.take(count)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| LogStoreFailure::resource_exhausted())?;
        bytes.extend_from_slice(source);
        Ok(bytes)
    }

    pub(super) fn string(&mut self, maximum: usize) -> Result<String, LogStoreFailure> {
        String::from_utf8(self.bytes(maximum)?).map_err(|_| LogStoreFailure::malformed_block())
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}
