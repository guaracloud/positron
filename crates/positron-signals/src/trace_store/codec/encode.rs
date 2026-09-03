use positron_domain::identity::TenantId;
use positron_domain::time::EventTime;
use positron_domain::value::{AttributeValueKind, ValueLimitProfile};

use super::super::details::{SpanAttributeSet, SpanEvent, SpanLink, SpanObservationDetails};
use super::super::failure::TraceStoreFailure;
use super::super::types::{StoredSpanObservation, TraceLimits, limits_for};
use super::format::{
    MAGIC, MAX_BLOCK_BYTES, MAX_RECORDS, VERSION, kind_tag, namespace_tag, quality_tag,
    sampling_tag, status_tag,
};

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
        encode_observation(&mut output, record, profile)?;
    }
    Ok(output)
}

fn encode_observation(
    output: &mut Vec<u8>,
    stored: &StoredSpanObservation,
    profile: &ValueLimitProfile,
) -> Result<(), TraceStoreFailure> {
    let limits = limits_for(profile)?;
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
        let namespace = super::format::namespace_index(attribute.namespace())?;
        occurrences_by_namespace[namespace] = occurrences_by_namespace[namespace]
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
    put_slice(output, &policy.digest())?;
    put_count(output, policy.applied_rules().len())?;
    for rule in policy.applied_rules() {
        put_bytes(output, rule.as_bytes())?;
    }
    put_i64(output, stored.ingest_time().instant().value())?;
    Ok(())
}

fn encode_details(
    output: &mut Vec<u8>,
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

fn encode_event(
    output: &mut Vec<u8>,
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

fn encode_link(
    output: &mut Vec<u8>,
    link: &SpanLink,
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
    if link.trace_state().len() > limits.key_path_bytes {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    put_slice(output, &link.trace_id())?;
    put_slice(output, &link.span_id())?;
    put_bytes(output, link.trace_state().as_bytes())?;
    put_u32(output, link.flags())?;
    put_u32(output, link.dropped_attributes_count())?;
    encode_span_attributes(output, link.attributes(), limits)
}

fn encode_span_attributes(
    output: &mut Vec<u8>,
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
    limits: &TraceLimits,
) -> Result<(), TraceStoreFailure> {
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
    }
    Ok(())
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

fn put_u8(output: &mut Vec<u8>, value: u8) -> Result<(), TraceStoreFailure> {
    put_slice(output, &[value])
}

fn put_u16(output: &mut Vec<u8>, value: u16) -> Result<(), TraceStoreFailure> {
    put_slice(output, &value.to_be_bytes())
}

fn put_u32(output: &mut Vec<u8>, value: u32) -> Result<(), TraceStoreFailure> {
    put_slice(output, &value.to_be_bytes())
}

fn put_count(output: &mut Vec<u8>, count: usize) -> Result<(), TraceStoreFailure> {
    let count = u16::try_from(count).map_err(|_| TraceStoreFailure::limit_exceeded())?;
    put_u16(output, count)
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
