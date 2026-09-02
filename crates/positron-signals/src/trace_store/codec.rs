//! Versioned native Trace Store Block codec.

use positron_domain::identity::TenantId;
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
    CandidateKeyValue, ValueLimitProfile,
};
use positron_kernel::CommittedBlock;

use super::failure::TraceStoreFailure;
use super::types::{SamplingDecision, SpanKind, SpanObservation, StoredSpanObservation};
use crate::{ScanCancellation, ScanObserver};

const MAGIC: &[u8; 8] = b"PTRCBL01";
const VERSION: u16 = 1;
pub(super) const MAX_RECORDS: usize = 1_024;
const MAX_ATTRIBUTES: usize = 3_072;
const MAX_VALUE_BYTES: usize = 65_536;
const MAX_KEY_BYTES: usize = 4_096;
const MAX_DEPTH: u8 = 128;
const MAX_BLOCK_BYTES: usize = 1_048_576;

pub(super) fn encode_block(
    tenant: TenantId,
    records: &[StoredSpanObservation],
) -> Result<Vec<u8>, TraceStoreFailure> {
    if records.is_empty() || records.len() > MAX_RECORDS {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut output = Vec::new();
    put_slice(&mut output, MAGIC)?;
    put_u16(&mut output, VERSION)?;
    put_slice(&mut output, &tenant.to_bytes())?;
    put_u16(
        &mut output,
        u16::try_from(records.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?,
    )?;
    for record in records {
        encode_observation(&mut output, record)?;
    }
    Ok(output)
}

fn encode_observation(
    output: &mut Vec<u8>,
    stored: &StoredSpanObservation,
) -> Result<(), TraceStoreFailure> {
    let observation = stored.observation();
    put_slice(output, &observation.trace_id())?;
    put_slice(output, &observation.span_id())?;
    match observation.parent_span_id() {
        Some(parent) => {
            put_u8(output, 1)?;
            put_slice(output, &parent)?;
        },
        None => put_u8(output, 0)?,
    }
    put_u8(output, kind_tag(observation.kind()))?;
    put_u8(output, sampling_tag(observation.sampling()))?;
    encode_time(output, observation.start_time())?;
    encode_time(output, observation.end_time())?;
    put_bytes(output, observation.name().as_bytes())?;
    put_u16(
        output,
        u16::try_from(observation.attributes().len())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
    )?;
    for attribute in observation.attributes() {
        put_u8(output, namespace_tag(attribute.namespace()))?;
        put_bytes(output, attribute.key().as_bytes())?;
        put_u16(
            output,
            u16::try_from(attribute.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?,
        )?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            encode_value(output, value, MAX_DEPTH)?;
        }
    }
    let policy = observation.policy_provenance();
    put_u64(output, policy.generation())?;
    put_slice(output, &policy.digest())?;
    put_u16(
        output,
        u16::try_from(policy.applied_rules().len())
            .map_err(|_| TraceStoreFailure::limit_exceeded())?,
    )?;
    for rule in policy.applied_rules() {
        put_bytes(output, rule.as_bytes())?;
    }
    put_i64(output, stored.ingest_time().instant().value())?;
    Ok(())
}

fn encode_time(output: &mut Vec<u8>, time: EventTime) -> Result<(), TraceStoreFailure> {
    put_u8(output, quality_tag(time.quality()))?;
    if let Some(value) = time.instant() {
        put_i64(output, value.value())?;
    }
    Ok(())
}

fn encode_value(
    output: &mut Vec<u8>,
    value: &positron_domain::value::ValidatedAttributeValue,
    depth: u8,
) -> Result<(), TraceStoreFailure> {
    use positron_domain::value::AttributeValueKind;
    match value.kind() {
        AttributeValueKind::Null => put_u8(output, 0)?,
        AttributeValueKind::Boolean => {
            put_u8(output, 1)?;
            put_u8(
                output,
                u8::from(
                    value
                        .as_boolean()
                        .ok_or_else(TraceStoreFailure::invalid_input)?,
                ),
            )?;
        },
        AttributeValueKind::SignedInteger => {
            put_u8(output, 2)?;
            put_i64(
                output,
                value
                    .as_signed_integer()
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
            )?;
        },
        AttributeValueKind::FloatingPoint => {
            put_u8(output, 3)?;
            put_u64(
                output,
                value
                    .as_floating_point_bits()
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
            )?;
        },
        AttributeValueKind::String => {
            put_u8(output, 4)?;
            put_bytes(
                output,
                value
                    .as_str()
                    .ok_or_else(TraceStoreFailure::invalid_input)?
                    .as_bytes(),
            )?;
        },
        AttributeValueKind::Bytes => {
            put_u8(output, 5)?;
            put_bytes(
                output,
                value
                    .as_bytes()
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
            )?;
        },
        AttributeValueKind::Array => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            put_u8(output, 6)?;
            let count = value
                .array_len()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            put_u16(
                output,
                u16::try_from(count).map_err(|_| TraceStoreFailure::limit_exceeded())?,
            )?;
            for index in 0..count {
                encode_value(
                    output,
                    value
                        .array_entry(index)
                        .ok_or_else(TraceStoreFailure::invalid_input)?,
                    next,
                )?;
            }
        },
        AttributeValueKind::KeyValueList => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            put_u8(output, 7)?;
            let count = value
                .key_value_list_len()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            put_u16(
                output,
                u16::try_from(count).map_err(|_| TraceStoreFailure::limit_exceeded())?,
            )?;
            for index in 0..count {
                let entry = value
                    .key_value_entry(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                put_bytes(output, entry.key().as_bytes())?;
                encode_value(output, entry.value(), next)?;
            }
        },
    }
    if output.len() > MAX_BLOCK_BYTES {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    Ok(())
}

pub(super) struct BlockDecode<'input> {
    pub(super) input: Input<'input>,
    count: usize,
}

impl<'input> BlockDecode<'input> {
    pub(super) fn observed(
        expected_tenant: TenantId,
        bytes: &'input [u8],
        cancellation: &'input dyn ScanCancellation,
        observer: &'input dyn ScanObserver,
    ) -> Result<Self, TraceStoreFailure> {
        let mut input = Input::observed(bytes, cancellation, observer);
        input.observe_component()?;
        if input.take(MAGIC.len())? != MAGIC {
            return Err(TraceStoreFailure::malformed_block());
        }
        if input.u16()? != VERSION {
            return Err(TraceStoreFailure::malformed_block());
        }
        let tenant = input.array::<16>()?;
        if tenant != expected_tenant.to_bytes() {
            return Err(TraceStoreFailure::physical_scope_mismatch());
        }
        let count = input.count(MAX_RECORDS)?;
        if count == 0 {
            return Err(TraceStoreFailure::malformed_block());
        }
        Ok(Self { input, count })
    }

    pub(super) const fn record_count(&self) -> usize {
        self.count
    }

    pub(super) fn decode_after(
        mut self,
        block: &CommittedBlock,
        skip: usize,
        limit: usize,
        cancellation: &dyn ScanCancellation,
    ) -> Result<DecodedBlock, TraceStoreFailure> {
        let skipped = skip.min(self.count);
        for _ in 0..skipped {
            check_cancel(cancellation)?;
            let (_, encoded_ingest_time) = decode_observation(&mut self.input)?;
            block
                .observe_ingest_time(encoded_ingest_time)
                .map_err(TraceStoreFailure::kernel)?;
        }
        let retained = self.count.saturating_sub(skipped).min(limit);
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(retained)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for _ in 0..retained {
            check_cancel(cancellation)?;
            let (observation, encoded_ingest_time) = decode_observation(&mut self.input)?;
            let ingest_time = block
                .observe_ingest_time(encoded_ingest_time)
                .map_err(TraceStoreFailure::kernel)?;
            self.input.observe_decoded_record()?;
            observations.push(StoredSpanObservation::new(observation, ingest_time));
        }
        // Validate and consume the unretained tail so malformed bytes never
        // disappear merely because the caller requested a small result bound.
        let mut tail = self.input.remaining_input();
        for _ in skipped + retained..self.count {
            check_cancel(cancellation)?;
            let (_, encoded_ingest_time) = decode_observation(&mut tail)?;
            block
                .observe_ingest_time(encoded_ingest_time)
                .map_err(TraceStoreFailure::kernel)?;
        }
        if !tail.is_empty() {
            return Err(TraceStoreFailure::malformed_block());
        }
        Ok(DecodedBlock { observations })
    }
}

pub(super) struct DecodedBlock {
    pub(super) observations: Vec<StoredSpanObservation>,
}

pub(super) fn decode_observation(
    input: &mut Input<'_>,
) -> Result<(SpanObservation, UnixNanoseconds), TraceStoreFailure> {
    input.observe_component()?;
    let trace_id = input.array::<16>()?;
    let span_id = input.array::<8>()?;
    let parent_span_id = match input.u8()? {
        0 => None,
        1 => Some(input.array::<8>()?),
        _ => return Err(TraceStoreFailure::malformed_block()),
    };
    let kind = decode_kind(input.u8()?)?;
    let sampling = decode_sampling(input.u8()?)?;
    let start = decode_time(input)?;
    let end = decode_time(input)?;
    let name = input.string(MAX_VALUE_BYTES)?;
    let attributes_count = input.count(MAX_ATTRIBUTES)?;
    let mut attributes = Vec::new();
    attributes
        .try_reserve_exact(attributes_count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..attributes_count {
        input.observe_component()?;
        let namespace = decode_namespace(input.u8()?)?;
        let key = input.string(MAX_KEY_BYTES)?;
        let count = input.count(MAX_RECORDS)?;
        if count == 0 {
            return Err(TraceStoreFailure::malformed_block());
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        for _ in 0..count {
            values.push(decode_value(input, MAX_DEPTH)?);
        }
        let candidate = AttributeOccurrenceSetCandidate::new(namespace, key, values);
        attributes.push(
            candidate
                .validate(ValueLimitProfile::release_1_system_maximum())
                .map_err(|_| TraceStoreFailure::malformed_block())?,
        );
    }
    let policy = decode_policy(input)?;
    let observation = SpanObservation::checked_native(
        trace_id,
        span_id,
        parent_span_id,
        name,
        start,
        end,
        attributes,
        kind,
        sampling,
        policy,
    )
    .map_err(|_| TraceStoreFailure::malformed_block())?;
    let ingest_time = UnixNanoseconds::new(input.i64()?);
    Ok((observation, ingest_time))
}

fn decode_policy(
    input: &mut Input<'_>,
) -> Result<positron_policy::PolicyProvenance, TraceStoreFailure> {
    let generation = input.u64()?;
    let digest = input.array::<32>()?;
    let count = input.count(positron_policy::PolicyProvenance::MAX_APPLIED_RULES)?;
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    for _ in 0..count {
        rules.push(input.string(positron_policy::PolicyProvenance::MAX_RULE_ID_BYTES)?);
    }
    positron_policy::PolicyProvenance::new(generation, digest, rules)
        .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_time(input: &mut Input<'_>) -> Result<EventTime, TraceStoreFailure> {
    let quality = decode_quality(input.u8()?)?;
    if quality == SourceTimeQuality::Missing {
        return Ok(EventTime::missing());
    }
    EventTime::received(UnixNanoseconds::new(input.i64()?), quality)
        .map_err(|_| TraceStoreFailure::malformed_block())
}

fn decode_value(
    input: &mut Input<'_>,
    depth: u8,
) -> Result<CandidateAttributeValue, TraceStoreFailure> {
    input.observe_component()?;
    match input.u8()? {
        0 => Ok(CandidateAttributeValue::null()),
        1 => match input.u8()? {
            0 => Ok(CandidateAttributeValue::boolean(false)),
            1 => Ok(CandidateAttributeValue::boolean(true)),
            _ => Err(TraceStoreFailure::malformed_block()),
        },
        2 => Ok(CandidateAttributeValue::signed_integer(input.i64()?)),
        3 => Ok(CandidateAttributeValue::floating_point_bits(input.u64()?)),
        4 => Ok(CandidateAttributeValue::string(
            input.string(MAX_VALUE_BYTES)?,
        )),
        5 => Ok(CandidateAttributeValue::bytes(
            input.bytes(MAX_VALUE_BYTES)?,
        )),
        6 => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::malformed_block)?;
            let count = input.count(MAX_RECORDS)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            for _ in 0..count {
                values.push(decode_value(input, next)?);
            }
            Ok(CandidateAttributeValue::array(values))
        },
        7 => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::malformed_block)?;
            let count = input.count(MAX_RECORDS)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| TraceStoreFailure::resource_exhausted())?;
            for _ in 0..count {
                let key = input.string(MAX_KEY_BYTES)?;
                values.push(CandidateKeyValue::new(key, decode_value(input, next)?));
            }
            Ok(CandidateAttributeValue::key_value_list(values))
        },
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

pub(super) struct Input<'a> {
    remaining: &'a [u8],
    cancellation: Option<&'a dyn ScanCancellation>,
    observer: Option<&'a dyn ScanObserver>,
}

impl<'a> Input<'a> {
    fn observed(
        bytes: &'a [u8],
        cancellation: &'a dyn ScanCancellation,
        observer: &'a dyn ScanObserver,
    ) -> Self {
        Self {
            remaining: bytes,
            cancellation: Some(cancellation),
            observer: Some(observer),
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], TraceStoreFailure> {
        self.poll()?;
        let (value, remaining) = self
            .remaining
            .split_at_checked(count)
            .ok_or_else(TraceStoreFailure::malformed_block)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, TraceStoreFailure> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(TraceStoreFailure::malformed_block)
    }

    fn u16(&mut self) -> Result<u16, TraceStoreFailure> {
        self.take(2)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, TraceStoreFailure> {
        self.take(4)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, TraceStoreFailure> {
        self.take(8)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(u64::from_be_bytes)
    }

    fn i64(&mut self) -> Result<i64, TraceStoreFailure> {
        self.take(8)
            .and_then(|value| {
                value
                    .try_into()
                    .map_err(|_| TraceStoreFailure::malformed_block())
            })
            .map(i64::from_be_bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TraceStoreFailure> {
        self.take(N).and_then(|value| {
            value
                .try_into()
                .map_err(|_| TraceStoreFailure::malformed_block())
        })
    }

    fn count(&mut self, maximum: usize) -> Result<usize, TraceStoreFailure> {
        let count = usize::from(self.u16()?);
        if count > maximum {
            Err(TraceStoreFailure::malformed_block())
        } else {
            Ok(count)
        }
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, TraceStoreFailure> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| TraceStoreFailure::malformed_block())?;
        if count > maximum {
            return Err(TraceStoreFailure::malformed_block());
        }
        let bytes = self.take(count)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(count)
            .map_err(|_| TraceStoreFailure::resource_exhausted())?;
        value.extend_from_slice(bytes);
        Ok(value)
    }

    fn string(&mut self, maximum: usize) -> Result<String, TraceStoreFailure> {
        let bytes = self.bytes(maximum)?;
        String::from_utf8(bytes).map_err(|_| TraceStoreFailure::malformed_block())
    }

    fn observe_component(&mut self) -> Result<(), TraceStoreFailure> {
        self.poll()?;
        if let Some(observer) = self.observer {
            observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
        }
        Ok(())
    }

    fn observe_decoded_record(&mut self) -> Result<(), TraceStoreFailure> {
        if let Some(observer) = self.observer {
            observer
                .observe_decoded_records(1)
                .map_err(TraceStoreFailure::observation)?;
        }
        Ok(())
    }

    pub(super) fn remaining_input(&self) -> Self {
        Self {
            remaining: self.remaining,
            cancellation: self.cancellation,
            observer: self.observer,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn poll(&self) -> Result<(), TraceStoreFailure> {
        if self.cancellation.is_some_and(|value| value.is_cancelled()) {
            return Err(TraceStoreFailure::cancelled());
        }
        Ok(())
    }
}

fn check_cancel(cancellation: &dyn ScanCancellation) -> Result<(), TraceStoreFailure> {
    if cancellation.is_cancelled() {
        Err(TraceStoreFailure::cancelled())
    } else {
        Ok(())
    }
}

fn put_slice(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TraceStoreFailure> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > MAX_BLOCK_BYTES)
    {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    output
        .try_reserve_exact(value.len())
        .map_err(|_| TraceStoreFailure::resource_exhausted())?;
    output.extend_from_slice(value);
    Ok(())
}

fn put_u8(output: &mut Vec<u8>, value: u8) -> Result<(), TraceStoreFailure> {
    put_slice(output, &[value])
}

fn put_u16(output: &mut Vec<u8>, value: u16) -> Result<(), TraceStoreFailure> {
    put_slice(output, &value.to_be_bytes())
}

fn put_u64(output: &mut Vec<u8>, value: u64) -> Result<(), TraceStoreFailure> {
    put_slice(output, &value.to_be_bytes())
}

fn put_i64(output: &mut Vec<u8>, value: i64) -> Result<(), TraceStoreFailure> {
    put_slice(output, &value.to_be_bytes())
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TraceStoreFailure> {
    let length = u32::try_from(value.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    put_slice(output, &length.to_be_bytes())?;
    put_slice(output, value)
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

fn decode_quality(tag: u8) -> Result<SourceTimeQuality, TraceStoreFailure> {
    match tag {
        1 => Ok(SourceTimeQuality::Usable),
        2 => Ok(SourceTimeQuality::Missing),
        3 => Ok(SourceTimeQuality::Zero),
        4 => Ok(SourceTimeQuality::Outlier),
        5 => Ok(SourceTimeQuality::Contradictory),
        _ => Err(TraceStoreFailure::malformed_block()),
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

fn decode_namespace(tag: u8) -> Result<AttributeNamespace, TraceStoreFailure> {
    match tag {
        1 => Ok(AttributeNamespace::Resource),
        2 => Ok(AttributeNamespace::InstrumentationScope),
        3 => Ok(AttributeNamespace::Record),
        4 => Ok(AttributeNamespace::Stream),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

fn kind_tag(kind: SpanKind) -> u8 {
    match kind {
        SpanKind::Unspecified => 0,
        SpanKind::Internal => 1,
        SpanKind::Server => 2,
        SpanKind::Client => 3,
        SpanKind::Producer => 4,
        SpanKind::Consumer => 5,
    }
}

fn decode_kind(tag: u8) -> Result<SpanKind, TraceStoreFailure> {
    match tag {
        0 => Ok(SpanKind::Unspecified),
        1 => Ok(SpanKind::Internal),
        2 => Ok(SpanKind::Server),
        3 => Ok(SpanKind::Client),
        4 => Ok(SpanKind::Producer),
        5 => Ok(SpanKind::Consumer),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

fn sampling_tag(sampling: SamplingDecision) -> u8 {
    match sampling {
        SamplingDecision::Unknown => 0,
        SamplingDecision::NotSampled => 1,
        SamplingDecision::Sampled => 2,
    }
}

fn decode_sampling(tag: u8) -> Result<SamplingDecision, TraceStoreFailure> {
    match tag {
        0 => Ok(SamplingDecision::Unknown),
        1 => Ok(SamplingDecision::NotSampled),
        2 => Ok(SamplingDecision::Sampled),
        _ => Err(TraceStoreFailure::malformed_block()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_kind, decode_namespace, decode_quality, decode_sampling, encode_block, kind_tag,
        namespace_tag, quality_tag, sampling_tag,
    };
    use crate::trace_store::{SamplingDecision, SpanKind, SpanObservation, StoredSpanObservation};
    use positron_domain::identity::TenantId;
    use positron_domain::time::SourceTimeQuality;
    use positron_domain::value::AttributeNamespace;
    use positron_kernel::{FixedLifecycleClockSource, LifecycleClock};

    #[test]
    fn codec_tags_round_trip_known_native_values() {
        for kind in [
            SpanKind::Unspecified,
            SpanKind::Internal,
            SpanKind::Server,
            SpanKind::Client,
            SpanKind::Producer,
            SpanKind::Consumer,
        ] {
            assert_eq!(decode_kind(kind_tag(kind)).expect("kind"), kind);
        }
        for sampling in [
            SamplingDecision::Unknown,
            SamplingDecision::NotSampled,
            SamplingDecision::Sampled,
        ] {
            assert_eq!(
                decode_sampling(sampling_tag(sampling)).expect("sampling"),
                sampling
            );
        }
        for quality in [
            SourceTimeQuality::Usable,
            SourceTimeQuality::Missing,
            SourceTimeQuality::Zero,
            SourceTimeQuality::Outlier,
            SourceTimeQuality::Contradictory,
        ] {
            assert_eq!(
                decode_quality(quality_tag(quality)).expect("quality"),
                quality
            );
        }
        for namespace in [
            AttributeNamespace::Resource,
            AttributeNamespace::InstrumentationScope,
            AttributeNamespace::Record,
            AttributeNamespace::Stream,
        ] {
            assert_eq!(
                decode_namespace(namespace_tag(namespace)).expect("namespace"),
                namespace
            );
        }
    }

    #[test]
    fn encoder_rejects_empty_and_overlarge_blocks_before_allocation() {
        let tenant = TenantId::from_bytes([0x41; 16]).expect("tenant");
        let empty = encode_block(tenant, &[]).expect_err("empty blocks are not native blocks");
        assert_eq!(empty.code(), crate::TraceStoreFailureCode::LimitExceeded);
        let observation = SpanObservation::checked_minimal(
            [0x71; 16],
            [0x72; 8],
            None,
            "encoded".to_owned(),
            None,
            None,
            Vec::new(),
            SpanKind::Internal,
            SamplingDecision::Unknown,
        )
        .expect("observation");
        let stored = StoredSpanObservation::new(
            observation,
            LifecycleClock::new(FixedLifecycleClockSource::new(
                positron_domain::time::UnixNanoseconds::new(1),
            ))
            .assign_ingest_time()
            .expect("ingest time"),
        );
        let records = vec![stored; super::MAX_RECORDS + 1];
        let overlarge = encode_block(tenant, &records)
            .expect_err("overlarge blocks are rejected before encoding");
        assert_eq!(
            overlarge.code(),
            crate::TraceStoreFailureCode::LimitExceeded
        );
    }
}
