use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::LogRecord;

use super::ReceiveFailure;
use super::{NativeLogAttribute, NativeLogBatch, NativeLogCandidate};
use positron_domain::value::{CandidateAttributeValue, CandidateKeyValue};

pub(super) fn decoded_record_bytes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &LogRecord,
    cloned_metadata: [&str; 4],
    maximum_nesting_depth: u16,
    maximum_decoded_record_bytes: usize,
) -> Result<usize, ReceiveFailure> {
    let mut bytes = add_decoded_bytes(
        record.severity_text.len(),
        record.event_name.len(),
        maximum_decoded_record_bytes,
    )?;
    for value in cloned_metadata {
        bytes = add_decoded_bytes(bytes, value.len(), maximum_decoded_record_bytes)?;
    }
    if let Some(body) = &record.body {
        bytes = add_decoded_bytes(
            bytes,
            decoded_value_bytes(body, maximum_nesting_depth, maximum_decoded_record_bytes)?,
            maximum_decoded_record_bytes,
        )?;
    }
    for attribute in resource.iter().chain(scope).chain(&record.attributes) {
        bytes = add_decoded_bytes(bytes, attribute.key.len(), maximum_decoded_record_bytes)?;
        if let Some(value) = &attribute.value {
            bytes = add_decoded_bytes(
                bytes,
                decoded_value_bytes(value, maximum_nesting_depth, maximum_decoded_record_bytes)?,
                maximum_decoded_record_bytes,
            )?;
        }
    }
    Ok(bytes)
}

pub(super) fn retained_record_heap_bytes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &LogRecord,
    cloned_metadata: [&String; 4],
) -> Result<usize, ReceiveFailure> {
    let attribute_count = resource
        .len()
        .checked_add(scope.len())
        .and_then(|count| count.checked_add(record.attributes.len()))
        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
    let attribute_capacity = attribute_count
        .checked_next_power_of_two()
        .unwrap_or(attribute_count);
    let mut bytes = attribute_capacity
        .checked_mul(std::mem::size_of::<NativeLogAttribute>())
        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
    for metadata in cloned_metadata {
        bytes = checked_retained_add(bytes, metadata.capacity())?;
    }
    bytes = checked_retained_add(bytes, record.severity_text.capacity())?;
    bytes = checked_retained_add(bytes, record.event_name.capacity())?;
    if let Some(body) = &record.body {
        bytes = checked_retained_add(bytes, retained_value_heap_bytes(body)?)?;
    }
    for attribute in resource.iter().chain(scope).chain(&record.attributes) {
        bytes = checked_retained_add(bytes, attribute.key.capacity())?;
        bytes = checked_retained_add(
            bytes,
            // `Vec::push` starts a non-zero-sized occurrence buffer at four slots.
            std::mem::size_of::<CandidateAttributeValue>()
                .checked_mul(4)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?,
        )?;
        if let Some(value) = &attribute.value {
            bytes = checked_retained_add(bytes, retained_value_heap_bytes(value)?)?;
        }
    }
    Ok(bytes)
}

pub(super) fn retained_batch_bytes(
    record_capacity: usize,
    record_heap_bytes: usize,
) -> Result<usize, ReceiveFailure> {
    let record_bytes = record_capacity
        .checked_mul(std::mem::size_of::<NativeLogCandidate>())
        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
    checked_retained_add(std::mem::size_of::<NativeLogBatch<'static>>(), record_bytes)
        .and_then(|bytes| checked_retained_add(bytes, record_heap_bytes))
}

pub(super) fn grouped_retained_bytes(
    batch_bytes: u64,
    record_count: usize,
) -> Result<u64, ReceiveFailure> {
    let per_record = std::mem::size_of::<NativeLogCandidate>()
        .checked_add(std::mem::size_of::<super::NativeLogAdmissionGroup<'static>>())
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<(
                positron_domain::routing::VirtualShardId,
                Vec<NativeLogCandidate>,
            )>())
        })
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
        .ok_or(ReceiveFailure::ValueLimitExceeded)?;
    let planning = record_count
        .checked_mul(per_record)
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<std::collections::BTreeMap<(), ()>>())
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<
                Vec<super::NativeLogAdmissionGroup<'static>>,
            >())
        });
    batch_bytes
        .checked_add(
            u64::try_from(planning.ok_or(ReceiveFailure::ValueLimitExceeded)?)
                .map_err(|_| ReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}

fn retained_value_heap_bytes(value: &AnyValue) -> Result<usize, ReceiveFailure> {
    match &value.value {
        None
        | Some(any_value::Value::BoolValue(_))
        | Some(any_value::Value::IntValue(_))
        | Some(any_value::Value::DoubleValue(_))
        | Some(any_value::Value::StringValueStrindex(_)) => Ok(0),
        Some(any_value::Value::StringValue(value)) => Ok(value.capacity()),
        Some(any_value::Value::BytesValue(value)) => Ok(value.capacity()),
        Some(any_value::Value::ArrayValue(array)) => {
            let mut bytes = array
                .values
                .capacity()
                .checked_mul(std::mem::size_of::<CandidateAttributeValue>())
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            for value in &array.values {
                bytes = checked_retained_add(bytes, retained_value_heap_bytes(value)?)?;
            }
            Ok(bytes)
        },
        Some(any_value::Value::KvlistValue(list)) => {
            let mut bytes = list
                .values
                .capacity()
                .checked_mul(std::mem::size_of::<CandidateKeyValue>())
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            for entry in &list.values {
                bytes = checked_retained_add(bytes, entry.key.capacity())?;
                if let Some(value) = &entry.value {
                    bytes = checked_retained_add(bytes, retained_value_heap_bytes(value)?)?;
                }
            }
            Ok(bytes)
        },
    }
}

fn checked_retained_add(left: usize, right: usize) -> Result<usize, ReceiveFailure> {
    left.checked_add(right)
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}

fn decoded_value_bytes(
    value: &AnyValue,
    remaining_depth: u16,
    maximum_decoded_record_bytes: usize,
) -> Result<usize, ReceiveFailure> {
    let Some(value) = &value.value else {
        return Ok(0);
    };
    match value {
        any_value::Value::StringValue(value) => Ok(value.len()),
        any_value::Value::BytesValue(value) => Ok(value.len()),
        any_value::Value::BoolValue(_) => Ok(1),
        any_value::Value::IntValue(_)
        | any_value::Value::DoubleValue(_)
        | any_value::Value::StringValueStrindex(_) => Ok(8),
        any_value::Value::ArrayValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value.values.iter().try_fold(0, |bytes, value| {
                add_decoded_bytes(
                    bytes,
                    decoded_value_bytes(value, next, maximum_decoded_record_bytes)?,
                    maximum_decoded_record_bytes,
                )
            })
        },
        any_value::Value::KvlistValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value.values.iter().try_fold(0, |bytes, entry| {
                let bytes =
                    add_decoded_bytes(bytes, entry.key.len(), maximum_decoded_record_bytes)?;
                let value_bytes = entry.value.as_ref().map_or(Ok(0), |value| {
                    decoded_value_bytes(value, next, maximum_decoded_record_bytes)
                })?;
                add_decoded_bytes(bytes, value_bytes, maximum_decoded_record_bytes)
            })
        },
    }
}

fn add_decoded_bytes(
    left: usize,
    right: usize,
    maximum_decoded_record_bytes: usize,
) -> Result<usize, ReceiveFailure> {
    left.checked_add(right)
        .filter(|bytes| *bytes <= maximum_decoded_record_bytes)
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}
