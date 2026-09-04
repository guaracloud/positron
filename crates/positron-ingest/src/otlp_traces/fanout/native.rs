use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::Span;
use positron_domain::value::{AttributeNamespace, ValueLimitSet};
use positron_signals::SpanAttributeSet;
use std::mem::size_of;

use super::super::TraceReceiveFailure;

const NATIVE_ATTRIBUTE_SET_BYTES: u64 = size_of::<SpanAttributeSet>() as u64;
const NATIVE_POLICY_ATTRIBUTE_BYTES: u64 =
    size_of::<positron_policy::NativePolicyAttribute>() as u64;
const NATIVE_CANDIDATE_VALUE_BYTES: u64 =
    size_of::<positron_domain::value::CandidateAttributeValue>() as u64;
const NATIVE_CANDIDATE_KEY_VALUE_BYTES: u64 =
    size_of::<positron_domain::value::CandidateKeyValue>() as u64;

const NATIVE_GROUPED_CANDIDATE_VALUE_BYTES: u64 = NATIVE_CANDIDATE_VALUE_BYTES;

pub(super) fn key_values_bytes(
    values: &[KeyValue],
    limits: &ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(native_attribute_footprint(value, limits)?)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })
}

pub(super) fn grouped_candidate_values_bytes(
    groups: &[(AttributeNamespace, &[KeyValue])],
    limits: &ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    let attribute_limit =
        usize::try_from(limits.dynamic_value().attributes_per_namespace().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    groups.iter().try_fold(0_u64, |total, (_, values)| {
        if values.len() > attribute_limit {
            return Err(TraceReceiveFailure::ValueLimitExceeded);
        }
        total
            .checked_add(
                u64::try_from(values.len())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                    .checked_mul(NATIVE_GROUPED_CANDIDATE_VALUE_BYTES)
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })
}

pub(super) fn span_detail_bytes(
    span: &Span,
    limits: &ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    let mut retained = 0_u64;
    for event in &span.events {
        let native_attribute_bytes = key_values_bytes(&event.attributes, limits)?;
        let grouped_candidate_bytes = grouped_candidate_values_bytes(
            &[(AttributeNamespace::Record, &event.attributes)],
            limits,
        )?;
        let native_attribute_slots = u64::try_from(event.attributes.capacity())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
            .checked_mul(NATIVE_ATTRIBUTE_SET_BYTES)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        let native_attributes = native_attribute_bytes
            .checked_add(grouped_candidate_bytes)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?
            .checked_add(native_attribute_slots)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        retained = retained
            .checked_add(native_attributes)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    for link in &span.links {
        let native_attribute_bytes = key_values_bytes(&link.attributes, limits)?;
        let grouped_candidate_bytes = grouped_candidate_values_bytes(
            &[(AttributeNamespace::Record, &link.attributes)],
            limits,
        )?;
        let native_attribute_slots = u64::try_from(link.attributes.capacity())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
            .checked_mul(NATIVE_ATTRIBUTE_SET_BYTES)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        let native_attributes = native_attribute_bytes
            .checked_add(grouped_candidate_bytes)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?
            .checked_add(native_attribute_slots)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        retained = retained
            .checked_add(native_attributes)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    Ok(retained)
}

fn native_attribute_footprint(
    value: &KeyValue,
    limits: &ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    let key =
        u64::try_from(value.key.capacity()).map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let value = value
        .value
        .as_ref()
        .map_or(Ok(NATIVE_CANDIDATE_VALUE_BYTES), |value| {
            native_any_value_footprint(
                value,
                limits,
                limits.dynamic_value().nesting_depth().value(),
            )
        })?;
    NATIVE_POLICY_ATTRIBUTE_BYTES
        .checked_add(key)
        .and_then(|bytes| bytes.checked_add(NATIVE_CANDIDATE_VALUE_BYTES))
        .and_then(|bytes| bytes.checked_add(value))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
}

fn native_any_value_footprint(
    value: &AnyValue,
    limits: &ValueLimitSet,
    remaining_depth: u16,
) -> Result<u64, TraceReceiveFailure> {
    let mut retained = NATIVE_CANDIDATE_VALUE_BYTES;
    match value.value.as_ref() {
        None
        | Some(
            any_value::Value::BoolValue(_)
            | any_value::Value::IntValue(_)
            | any_value::Value::DoubleValue(_)
            | any_value::Value::StringValueStrindex(_),
        ) => {},
        Some(any_value::Value::StringValue(value)) => {
            retained = retained
                .checked_add(
                    u64::try_from(value.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        },
        Some(any_value::Value::BytesValue(value)) => {
            retained = retained
                .checked_add(
                    u64::try_from(value.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        },
        Some(any_value::Value::ArrayValue(value)) => {
            let maximum = usize::try_from(limits.dynamic_value().array_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.values.len() > maximum {
                return Err(TraceReceiveFailure::ValueLimitExceeded);
            }
            let next_depth = remaining_depth
                .checked_sub(1)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            retained = retained
                .checked_add(
                    u64::try_from(value.values.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                        .checked_mul(NATIVE_CANDIDATE_VALUE_BYTES)
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            for child in &value.values {
                retained = retained
                    .checked_add(native_any_value_footprint(child, limits, next_depth)?)
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            }
        },
        Some(any_value::Value::KvlistValue(value)) => {
            let maximum = usize::try_from(limits.dynamic_value().key_value_list_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.values.len() > maximum {
                return Err(TraceReceiveFailure::ValueLimitExceeded);
            }
            let next_depth = remaining_depth
                .checked_sub(1)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            retained = retained
                .checked_add(
                    u64::try_from(value.values.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                        .checked_mul(NATIVE_CANDIDATE_KEY_VALUE_BYTES)
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            for entry in &value.values {
                retained = retained
                    .checked_add(
                        u64::try_from(entry.key.capacity())
                            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                    )
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
                if let Some(value) = entry.value.as_ref() {
                    retained = retained
                        .checked_add(native_any_value_footprint(value, limits, next_depth)?)
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
                }
            }
        },
    }
    Ok(retained)
}
