use positron_domain::time::EventTime;
use positron_domain::value::{
    AttributeValueKind, NATIVE_VALUE_PAYLOAD_CHUNK_BYTES, ValueLimitProfile,
};

use super::super::details::{SpanAttributeSet, SpanObservationDetails};
use super::super::failure::TraceStoreFailure;
use super::super::observation::SpanObservation;
use super::super::types::{TraceLimits, limits_for};
use crate::{ScanCancellation, ScanObserver};

trait SizeObserver {
    fn observe_structure(&mut self) -> Result<(), TraceStoreFailure>;
    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), TraceStoreFailure>;
}

struct UnobservedSize;

impl SizeObserver for UnobservedSize {
    fn observe_structure(&mut self) -> Result<(), TraceStoreFailure> {
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), TraceStoreFailure> {
        Ok(())
    }
}

struct ObservedSize<'a> {
    cancellation: &'a dyn ScanCancellation,
    observer: &'a dyn ScanObserver,
}

impl SizeObserver for ObservedSize<'_> {
    fn observe_structure(&mut self) -> Result<(), TraceStoreFailure> {
        super::super::scan::check_cancel(self.cancellation)?;
        self.observer
            .observe_work(1)
            .map_err(TraceStoreFailure::observation)
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), TraceStoreFailure> {
        for _ in payload.chunks(NATIVE_VALUE_PAYLOAD_CHUNK_BYTES) {
            self.observe_structure()?;
        }
        Ok(())
    }
}

/// Returns one canonical encoded Trace Store record length without allocating.
///
/// The result includes every record field, native detail payload, policy
/// provenance, and the fixed eight-byte ingest-time field. It deliberately
/// excludes the block header and is the shared semantic record-size authority
/// for receiver admission and durable encoding.
pub(crate) fn encoded_record_bytes_with_profile(
    profile: &ValueLimitProfile,
    observation: &SpanObservation,
) -> Result<usize, TraceStoreFailure> {
    encoded_record_bytes_with_limits(observation, &limits_for(profile)?)
}

pub(crate) fn encoded_record_bytes_with_profile_observed(
    profile: &ValueLimitProfile,
    observation: &SpanObservation,
    cancellation: &dyn ScanCancellation,
    observer: &dyn ScanObserver,
) -> Result<usize, TraceStoreFailure> {
    let mut observed = ObservedSize {
        cancellation,
        observer,
    };
    encoded_record_bytes_with_limits_using(observation, &limits_for(profile)?, &mut observed)
}

pub(crate) fn encoded_record_bytes_with_limits(
    observation: &SpanObservation,
    limits: &TraceLimits,
) -> Result<usize, TraceStoreFailure> {
    let mut unobserved = UnobservedSize;
    encoded_record_bytes_with_limits_using(observation, limits, &mut unobserved)
}

fn encoded_record_bytes_with_limits_using<O: SizeObserver>(
    observation: &SpanObservation,
    limits: &TraceLimits,
    observer: &mut O,
) -> Result<usize, TraceStoreFailure> {
    let bytes = encoded_observation_length(observation, limits, observer)?;
    if bytes > limits.encoded_bytes {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    Ok(bytes)
}

fn encoded_observation_length(
    observation: &SpanObservation,
    limits: &TraceLimits,
    observer: &mut impl SizeObserver,
) -> Result<usize, TraceStoreFailure> {
    observer.observe_structure()?;
    if observation.name().is_empty() || observation.name().len() > limits.key_path_bytes {
        return Err(TraceStoreFailure::invalid_input());
    }
    if observation.attributes().len() > limits.attribute_sets {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut occurrences_by_namespace = [0_usize; 3];
    let mut bytes = 24_usize;
    bytes = add_length(bytes, 1)?;
    bytes = add_length(
        bytes,
        usize::from(observation.parent_span_id().is_some()) * 8,
    )?;
    bytes = add_length(bytes, 2)?;
    bytes = add_length(bytes, encoded_time_length(observation.start_time()))?;
    bytes = add_length(bytes, encoded_time_length(observation.end_time()))?;
    observer.observe_payload(observation.name().as_bytes())?;
    bytes = add_bytes_length(bytes, observation.name().len())?;
    bytes = add_length(bytes, 2)?;
    for attribute in observation.attributes() {
        observer.observe_structure()?;
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
        bytes = add_length(bytes, 1)?;
        observer.observe_payload(attribute.key().as_bytes())?;
        bytes = add_bytes_length(bytes, attribute.key().len())?;
        bytes = add_length(bytes, 2)?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            bytes = add_length(
                bytes,
                encoded_value_length(value, limits.nesting_depth, limits, observer)?,
            )?;
        }
    }
    bytes = add_length(
        bytes,
        encoded_details_length(observation.details(), limits, observer)?,
    )?;
    let policy = observation.policy_provenance();
    bytes = add_length(bytes, 8 + 32 + 2)?;
    for rule in policy.applied_rules() {
        observer.observe_structure()?;
        observer.observe_payload(rule.as_bytes())?;
        bytes = add_bytes_length(bytes, rule.len())?;
    }
    add_length(bytes, 8)
}

fn encoded_details_length(
    details: &SpanObservationDetails,
    limits: &TraceLimits,
    observer: &mut impl SizeObserver,
) -> Result<usize, TraceStoreFailure> {
    observer.observe_structure()?;
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
    let mut bytes = 0_usize;
    observer.observe_payload(details.trace_state().as_bytes())?;
    bytes = add_bytes_length(bytes, details.trace_state().len())?;
    bytes = add_length(bytes, 4 + 1)?;
    observer.observe_payload(details.status().message().as_bytes())?;
    bytes = add_bytes_length(bytes, details.status().message().len())?;
    bytes = add_length(bytes, 4 * 4)?;
    observer.observe_payload(details.resource().schema_url().as_bytes())?;
    bytes = add_bytes_length(bytes, details.resource().schema_url().len())?;
    observer.observe_payload(details.scope().name().as_bytes())?;
    bytes = add_bytes_length(bytes, details.scope().name().len())?;
    observer.observe_payload(details.scope().version().as_bytes())?;
    bytes = add_bytes_length(bytes, details.scope().version().len())?;
    bytes = add_length(bytes, 4)?;
    observer.observe_payload(details.scope().schema_url().as_bytes())?;
    bytes = add_bytes_length(bytes, details.scope().schema_url().len())?;
    bytes = add_length(bytes, 2)?;
    for event in details.events() {
        observer.observe_structure()?;
        if event.name().is_empty() || event.name().len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::invalid_input());
        }
        bytes = add_length(bytes, encoded_time_length(event.timestamp()))?;
        observer.observe_payload(event.name().as_bytes())?;
        bytes = add_bytes_length(bytes, event.name().len())?;
        bytes = add_length(bytes, 4)?;
        bytes = add_length(
            bytes,
            encoded_span_attributes_length(event.attributes(), limits, observer)?,
        )?;
    }
    bytes = add_length(bytes, 2)?;
    for link in details.links() {
        observer.observe_structure()?;
        if link.trace_state().len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        bytes = add_length(bytes, 16 + 8)?;
        observer.observe_payload(link.trace_state().as_bytes())?;
        bytes = add_bytes_length(bytes, link.trace_state().len())?;
        bytes = add_length(bytes, 4 + 4)?;
        bytes = add_length(
            bytes,
            encoded_span_attributes_length(link.attributes(), limits, observer)?,
        )?;
    }
    Ok(bytes)
}

fn encoded_span_attributes_length(
    attributes: &[SpanAttributeSet],
    limits: &TraceLimits,
    observer: &mut impl SizeObserver,
) -> Result<usize, TraceStoreFailure> {
    observer.observe_structure()?;
    if attributes.len() > super::super::details::MAX_DETAIL_COLLECTION {
        return Err(TraceStoreFailure::limit_exceeded());
    }
    let mut occurrences = 0_usize;
    let mut bytes = 2_usize;
    for attribute in attributes {
        observer.observe_structure()?;
        if attribute.key().len() > limits.key_path_bytes {
            return Err(TraceStoreFailure::limit_exceeded());
        }
        occurrences = occurrences
            .checked_add(attribute.len())
            .filter(|count| *count <= limits.occurrences_per_namespace)
            .ok_or_else(TraceStoreFailure::limit_exceeded)?;
        observer.observe_payload(attribute.key().as_bytes())?;
        bytes = add_bytes_length(bytes, attribute.key().len())?;
        bytes = add_length(bytes, 2)?;
        for index in 0..attribute.len() {
            let value = attribute
                .occurrence(index)
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            bytes = add_length(
                bytes,
                encoded_value_length(value, limits.nesting_depth, limits, observer)?,
            )?;
        }
    }
    Ok(bytes)
}

fn encoded_value_length(
    value: &positron_domain::value::ValidatedAttributeValue,
    depth: u8,
    limits: &TraceLimits,
    observer: &mut impl SizeObserver,
) -> Result<usize, TraceStoreFailure> {
    observer.observe_structure()?;
    if value.marker_action().is_some() {
        return Ok(3);
    }
    if value.truncation_action().is_some() {
        return add_length(
            3,
            encoded_value_length(
                value
                    .truncated_value()
                    .ok_or_else(TraceStoreFailure::invalid_input)?,
                depth,
                limits,
                observer,
            )?,
        );
    }
    match value.kind() {
        AttributeValueKind::Null => Ok(1),
        AttributeValueKind::Boolean => Ok(2),
        AttributeValueKind::SignedInteger | AttributeValueKind::FloatingPoint => Ok(9),
        AttributeValueKind::String => {
            let text = value
                .as_str()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if text.len() > limits.value_bytes {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            observer.observe_payload(text.as_bytes())?;
            add_bytes_length(1, text.len())
        },
        AttributeValueKind::Bytes => {
            let bytes = value
                .as_bytes()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if bytes.len() > limits.value_bytes {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            observer.observe_payload(bytes)?;
            add_bytes_length(1, bytes.len())
        },
        AttributeValueKind::Array => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            let count = value
                .array_len()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if count > limits.array_entries {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            let mut bytes = 3_usize;
            for index in 0..count {
                let child = value
                    .array_entry(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                bytes = add_length(bytes, encoded_value_length(child, next, limits, observer)?)?;
            }
            Ok(bytes)
        },
        AttributeValueKind::KeyValueList => {
            let next = depth
                .checked_sub(1)
                .ok_or_else(TraceStoreFailure::limit_exceeded)?;
            let count = value
                .key_value_list_len()
                .ok_or_else(TraceStoreFailure::invalid_input)?;
            if count > limits.key_value_list_entries {
                return Err(TraceStoreFailure::limit_exceeded());
            }
            let mut bytes = 3_usize;
            for index in 0..count {
                observer.observe_structure()?;
                let entry = value
                    .key_value_entry(index)
                    .ok_or_else(TraceStoreFailure::invalid_input)?;
                if entry.key().len() > limits.key_path_bytes {
                    return Err(TraceStoreFailure::limit_exceeded());
                }
                observer.observe_payload(entry.key().as_bytes())?;
                bytes = add_bytes_length(bytes, entry.key().len())?;
                bytes = add_length(
                    bytes,
                    encoded_value_length(entry.value(), next, limits, observer)?,
                )?;
            }
            Ok(bytes)
        },
        AttributeValueKind::Marker => Err(TraceStoreFailure::invalid_input()),
    }
}

fn encoded_time_length(time: EventTime) -> usize {
    1 + usize::from(time.instant().is_some() || time.source_value().is_some()) * 8
}

fn add_bytes_length(total: usize, bytes: usize) -> Result<usize, TraceStoreFailure> {
    add_length(total, 4 + bytes)
}

fn add_length(total: usize, bytes: usize) -> Result<usize, TraceStoreFailure> {
    total
        .checked_add(bytes)
        .ok_or_else(TraceStoreFailure::limit_exceeded)
}
