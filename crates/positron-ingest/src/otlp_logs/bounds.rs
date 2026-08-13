use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::LogRecord;

use super::ReceiveFailure;

pub(super) const MAX_DECODED_BATCH_BYTES: usize = 1_048_576;
const MAX_DECODED_RECORD_BYTES: usize = 524_288;
const MAX_NESTING_DEPTH: u16 = 16;

pub(super) fn decoded_record_bytes(
    resource: &[KeyValue],
    scope: &[KeyValue],
    record: &LogRecord,
) -> Result<usize, ReceiveFailure> {
    let mut bytes = record.severity_text.len();
    if let Some(body) = &record.body {
        bytes = add_decoded_bytes(bytes, decoded_value_bytes(body, MAX_NESTING_DEPTH)?)?;
    }
    for attribute in resource.iter().chain(scope).chain(&record.attributes) {
        bytes = add_decoded_bytes(bytes, attribute.key.len())?;
        if let Some(value) = &attribute.value {
            bytes = add_decoded_bytes(bytes, decoded_value_bytes(value, MAX_NESTING_DEPTH)?)?;
        }
    }
    Ok(bytes)
}

fn decoded_value_bytes(value: &AnyValue, remaining_depth: u16) -> Result<usize, ReceiveFailure> {
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
                add_decoded_bytes(bytes, decoded_value_bytes(value, next)?)
            })
        },
        any_value::Value::KvlistValue(value) => {
            let next = remaining_depth
                .checked_sub(1)
                .ok_or(ReceiveFailure::ValueLimitExceeded)?;
            value.values.iter().try_fold(0, |bytes, entry| {
                let bytes = add_decoded_bytes(bytes, entry.key.len())?;
                let value_bytes = entry
                    .value
                    .as_ref()
                    .map_or(Ok(0), |value| decoded_value_bytes(value, next))?;
                add_decoded_bytes(bytes, value_bytes)
            })
        },
    }
}

fn add_decoded_bytes(left: usize, right: usize) -> Result<usize, ReceiveFailure> {
    left.checked_add(right)
        .filter(|bytes| *bytes <= MAX_DECODED_RECORD_BYTES)
        .ok_or(ReceiveFailure::ValueLimitExceeded)
}
