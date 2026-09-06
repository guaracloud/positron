use positron_domain::identity::TenantId;
use positron_domain::time::EventTime;
use positron_domain::value::{AttributeValueKind, MarkerAction, ValueLimitProfile};

use crate::{ScanCancellation, ScanObserver};

use super::super::details::{SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails};
use super::super::failure::TraceStoreFailure;
use super::super::types::{StoredSpanObservation, TraceLimits, limits_for};
use super::encoded_size::encoded_record_bytes_with_limits;
use super::format::{
    MAGIC, MAX_BLOCK_BYTES, MAX_RECORDS, OUT_OF_RANGE_TIME_TAG, VERSION, kind_tag, namespace_tag,
    quality_tag, sampling_tag, status_tag,
};

const SEMANTIC_KEY_WORK_CHUNK_BYTES: usize = 4_096;

trait EncodeOutput {
    fn put_slice(&mut self, value: &[u8]) -> Result<(), TraceStoreFailure>;
}

impl EncodeOutput for Vec<u8> {
    fn put_slice(&mut self, value: &[u8]) -> Result<(), TraceStoreFailure> {
        put_slice(self, value)
    }
}

struct ObservedSemanticOutput<'a> {
    bytes: Vec<u8>,
    cancellation: &'a dyn ScanCancellation,
    observer: &'a dyn ScanObserver,
}

impl ObservedSemanticOutput<'_> {
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl EncodeOutput for ObservedSemanticOutput<'_> {
    fn put_slice(&mut self, value: &[u8]) -> Result<(), TraceStoreFailure> {
        for chunk in value.chunks(SEMANTIC_KEY_WORK_CHUNK_BYTES) {
            super::super::scan::check_cancel(self.cancellation)?;
            self.observer
                .observe_work(1)
                .map_err(TraceStoreFailure::observation)?;
            put_slice(&mut self.bytes, chunk)?;
        }
        Ok(())
    }
}

#[cfg(any(test, fuzzing))]
pub(crate) fn encode_block(
    tenant: TenantId,
    records: &[StoredSpanObservation],
) -> Result<Vec<u8>, TraceStoreFailure> {
    let profile = ValueLimitProfile::release_1_system_maximum();
    encode_block_with_profile(&profile, tenant, records)
}

pub(crate) fn encode_block_with_profile(
    profile: &ValueLimitProfile,
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
    put_count(&mut output, records.len())?;
    for record in records {
        encoded_record_bytes_with_limits(record.observation(), &limits_for(profile)?)?;
        encode_observation(&mut output, record, profile)?;
    }
    Ok(output)
}

fn encode_observation<O: EncodeOutput>(
    output: &mut O,
    stored: &StoredSpanObservation,
    profile: &ValueLimitProfile,
) -> Result<(), TraceStoreFailure> {
    encode_semantic_observation(output, stored.observation(), profile)?;
    put_i64(output, stored.ingest_time().instant().value())
}

/// Encodes the complete immutable native observation without its per-commit
/// ingest time. These bytes are an exact, collision-free semantic key for
/// logical retry consolidation: retry metadata is excluded while every native
/// value distinction remains present.
pub(crate) fn encode_semantic_observation_with_profile_observed(
    profile: &ValueLimitProfile,
    observation: &super::super::observation::SpanObservation,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<Vec<u8>, TraceStoreFailure> {
    let encoded = encoded_record_bytes_with_limits(observation, &limits_for(profile)?)?;
    let expected = encoded
        .checked_sub(8)
        .ok_or_else(TraceStoreFailure::invalid_input)?;
    let mut output = ObservedSemanticOutput {
        bytes: Vec::new(),
        cancellation,
        observer,
    };
    encode_semantic_observation(&mut output, observation, profile)?;
    let output = output.into_bytes();
    if output.len() == expected {
        Ok(output)
    } else {
        Err(TraceStoreFailure::invalid_input())
    }
}

fn encode_semantic_observation<O: EncodeOutput>(
    output: &mut O,
    observation: &super::super::observation::SpanObservation,
    profile: &ValueLimitProfile,
) -> Result<(), TraceStoreFailure> {
    let limits = limits_for(profile)?;
    output.put_slice(&observation.trace_id())?;
    output.put_slice(&observation.span_id())?;
    match observation.parent_span_id() {
        Some(parent) => {
            put_u8(output, 1)?;
            output.put_slice(&parent)?;
        },
        None => put_u8(output, 0)?,
    }
    put_u8(output, kind_tag(observation.kind()))?;
    put_u8(output, sampling_tag(observation.sampling()))?;
    encode_time(output, observation.start_time())?;
    encode_time(output, observation.end_time())?;
    put_bytes(output, observation.name().as_bytes())?;
    put_count(output, observation.attributes().len())?;
    for attribute in observation.attributes() {
        put_u8(output, namespace_tag(attribute.namespace())?)?;
        put_bytes(output, attribute.key().as_bytes())?;
        put_count(output, attribute.len())?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            encode_value(output, value, limits.nesting_depth, &limits)?;
        }
    }
    if observation.name().is_empty() || observation.name().len() > limits.key_path_bytes {
        return Err(TraceStoreFailure::invalid_input());
    }
    if observation.attributes().len() > limits.attribute_sets {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut occurrences_by_namespace = [0_usize; 3];
    for attribute in observation.attributes() {
        if attribute.key().len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        let namespace = super::format::namespace_index(attribute.namespace())
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        let occurrences = occurrences_by_namespace
            .get_mut(namespace)
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        *occurrences = occurrences
            .checked_add(attribute.len())
            .filter(|count| *count <= limits.occurrences_per_namespace)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
    }
    let _ = observation
        .details()
        .decoded_size_bytes(limits.decoded_bytes)?;
    encode_details(output, observation.details(), &limits)?;
    let policy = observation.policy_provenance();
    put_u64(output, policy.generation())?;
    output.put_slice(&policy.digest())?;
    put_count(output, policy.applied_rules().len())?;
    for rule in policy.applied_rules() {
        put_bytes(output, rule.as_bytes())?;
    }
    Ok(())
}

fn encode_details<O: EncodeOutput>(
    output: &mut O,
    details: &SpanObservationDetails,
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
    if details.trace_state().len() > limits.key_path_bytes
        || details.status().message().len() > limits.key_path_bytes
        || details.resource().schema_url().len() > limits.key_path_bytes
        || details.scope().name().len() > limits.key_path_bytes
        || details.scope().version().len() > limits.key_path_bytes
        || details.scope().schema_url().len() > limits.key_path_bytes
        || details.events().len() > super::super::details::MAX_DETAIL_COLLECTION
        || details.links().len() > super::super::details::MAX_DETAIL_COLLECTION
    {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    put_bytes(output, details.trace_state().as_bytes())?;
    put_u32(output, details.flags())?;
    put_u8(output, status_tag(details.status().code()))?;
    put_bytes(output, details.status().message().as_bytes())?;
    put_u32(output, details.dropped_attributes_count())?;
    put_u32(output, details.dropped_events_count())?;
    put_u32(output, details.dropped_links_count())?;
    put_u32(output, details.resource().dropped_attributes_count())?;
    put_bytes(output, details.resource().schema_url().as_bytes())?;
    put_bytes(output, details.scope().name().as_bytes())?;
    put_bytes(output, details.scope().version().as_bytes())?;
    put_u32(output, details.scope().dropped_attributes_count())?;
    put_bytes(output, details.scope().schema_url().as_bytes())?;
    put_count(output, details.events().len())?;
    for event in details.events() {
        encode_event(output, event, limits)?;
    }
    put_count(output, details.links().len())?;
    for link in details.links() {
        encode_link(output, link, limits)?;
    }
    Ok(())
}

fn encode_event<O: EncodeOutput>(
    output: &mut O,
    event: &SpanEvent,
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
    if event.name().is_empty() || event.name().len() > limits.key_path_bytes {
        return Err(TraceStoreFailure::invalid_input());
    }
    encode_time(output, event.timestamp())?;
    put_bytes(output, event.name().as_bytes())?;
    put_u32(output, event.dropped_attributes_count())?;
    encode_span_attributes(output, event.attributes(), limits)
}

fn encode_link<O: EncodeOutput>(
    output: &mut O,
    link: &SpanLink,
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
    if link.trace_state().len() > limits.key_path_bytes {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    output.put_slice(&link.trace_id())?;
    output.put_slice(&link.span_id())?;
    put_bytes(output, link.trace_state().as_bytes())?;
    put_u32(output, link.flags())?;
    put_u32(output, link.dropped_attributes_count())?;
    encode_span_attributes(output, link.attributes(), limits)
}

fn encode_span_attributes<O: EncodeOutput>(
    output: &mut O,
    attributes: &[SpanAttributeSet],
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
    if attributes.len() > super::super::details::MAX_DETAIL_COLLECTION {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut occurrences = 0_usize;
    put_count(output, attributes.len())?;
    for attribute in attributes {
        if attribute.key().len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        occurrences = occurrences
            .checked_add(attribute.len())
            .filter(|count| *count <= limits.occurrences_per_namespace)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        put_bytes(output, attribute.key().as_bytes())?;
        put_count(output, attribute.len())?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            encode_value(output, value, limits.nesting_depth, limits)?;
        }
    }
    Ok(())
}

fn encode_time<O: EncodeOutput>(output: &mut O, time: EventTime) -> Result<(), TraceStoreFailure> {
    if let Some(value) = time.source_value().filter(|value| *value > i64::MAX as u64) {
        put_u8(output, OUT_OF_RANGE_TIME_TAG)?;
        put_u64(output, value)?;
        return Ok(());
    }
    put_u8(output, quality_tag(time.quality()))?;
    if let Some(value) = time.instant() {
        put_i64(output, value.value())?;
    }
    Ok(())
}

fn encode_value<O: EncodeOutput>(
    output: &mut O,
    value: &positron_domain::value::ValidatedAttributeValue,
    depth: u8,
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
    if let Some(action) = value.marker_action() {
        put_u8(output, 8)?;
        put_u8(output, marker_action_tag(action))?;
        put_u8(
            output,
            native_kind_tag(
                value
                    .marker_original_kind()
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
            )?,
        )?;
        return Ok(());
    }
    if let Some(action) = value.truncation_action() {
        let child = value
            .truncated_value()
            .ok_or_else(TraceStoreFailure::invalid_input)?;
        put_u8(output, 8)?;
        put_u8(output, marker_action_tag(action))?;
        put_u8(output, native_kind_tag(child.kind())?)?;
        return encode_value(output, child, depth, limits);
    }
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
            let text = value
                .as_str()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if text.len() > limits.value_bytes {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            put_bytes(output, text.as_bytes())?;
        },
        AttributeValueKind::Bytes => {
            put_u8(output, 5)?;
            let bytes = value
                .as_bytes()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if bytes.len() > limits.value_bytes {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            put_bytes(output, bytes)?;
        },
        AttributeValueKind::Array => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            put_u8(output, 6)?;
            let count = value
                .array_len()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if count > limits.array_entries {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            put_count(output, count)?;
            for index in 0..count {
                encode_value(
                    output,
                    value
                        .array_entry(index)
                        .ok_or_else(TraceStoreFailure::invalid_input)?,
                    next,
                    limits,
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
            if count > limits.key_value_list_entries {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            put_count(output, count)?;
            for index in 0..count {
                let entry = value
                    .key_value_entry(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                if entry.key().len() > limits.key_path_bytes {
                    return Err(TraceStoreFailure::limit_exceeded());
                }
                put_bytes(output, entry.key().as_bytes())?;
                encode_value(output, entry.value(), next, limits)?;
            }
        },
        AttributeValueKind::Marker => return Err(TraceStoreFailure::invalid_input()),
    }
    Ok(())
}

fn marker_action_tag(action: MarkerAction) -> u8 {
    match action {
        MarkerAction::Removed => 0,
        MarkerAction::Redacted => 1,
        MarkerAction::TruncatedBytes => 2,
        MarkerAction::TruncatedElements => 3,
    }
}

fn native_kind_tag(kind: AttributeValueKind) -> Result<u8, TraceStoreFailure> {
    match kind {
        AttributeValueKind::Null => Ok(0),
        AttributeValueKind::Boolean => Ok(1),
        AttributeValueKind::SignedInteger => Ok(2),
        AttributeValueKind::FloatingPoint => Ok(3),
        AttributeValueKind::String => Ok(4),
        AttributeValueKind::Bytes => Ok(5),
        AttributeValueKind::Array => Ok(6),
        AttributeValueKind::KeyValueList => Ok(7),
        AttributeValueKind::Marker => Err(TraceStoreFailure::invalid_input()),
    }
}

pub(crate) fn put_slice(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TraceStoreFailure> {
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

fn put_u8<O: EncodeOutput>(output: &mut O, value: u8) -> Result<(), TraceStoreFailure> {
    output.put_slice(&[value])
}

fn put_u16<O: EncodeOutput>(output: &mut O, value: u16) -> Result<(), TraceStoreFailure> {
    output.put_slice(&value.to_be_bytes())
}

fn put_u32<O: EncodeOutput>(output: &mut O, value: u32) -> Result<(), TraceStoreFailure> {
    output.put_slice(&value.to_be_bytes())
}

fn put_count<O: EncodeOutput>(output: &mut O, count: usize) -> Result<(), TraceStoreFailure> {
    let count = u16::try_from(count).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    put_u16(output, count)
}

fn put_u64<O: EncodeOutput>(output: &mut O, value: u64) -> Result<(), TraceStoreFailure> {
    output.put_slice(&value.to_be_bytes())
}

fn put_i64<O: EncodeOutput>(output: &mut O, value: i64) -> Result<(), TraceStoreFailure> {
    output.put_slice(&value.to_be_bytes())
}

fn put_bytes<O: EncodeOutput>(output: &mut O, value: &[u8]) -> Result<(), TraceStoreFailure> {
    let length = u32::try_from(value.len()).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    output.put_slice(&length.to_be_bytes())?;
    output.put_slice(value)
}
