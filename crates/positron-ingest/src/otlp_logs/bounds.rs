use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::LogRecord;

use super::ReceiveFailure;

pub(super) fn decoded_record_bytes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &LogRecord,
    cloned_metadata: [&str; 4],
    maximum_nesting_depth: u16,
    maximum_decoded_record_bytes: usize,
) -> Result<usize, ReceiveFailure> {
    let mut bytes = record.severity_text.len();
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
