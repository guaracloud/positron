use opentelemetry_proto::tonic::common::v1::{AnyValue, EntityRef, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::Span;
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use positron_domain::value::ValueLimitSet;
use prost::Message;
use std::mem::size_of;

use super::super::TraceReceiveFailure;

const WIRE_KEY_VALUE_SLOT_BYTES: u64 = size_of::<KeyValue>() as u64;
const WIRE_ANY_VALUE_SLOT_BYTES: u64 = size_of::<AnyValue>() as u64;
const WIRE_ENTITY_REF_SLOT_BYTES: u64 = size_of::<EntityRef>() as u64;
const WIRE_EVENT_SLOT_BYTES: u64 = size_of::<Event>() as u64;
const WIRE_LINK_SLOT_BYTES: u64 = size_of::<Link>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct KeyValuesFootprint {
    pub(super) wire_bytes: u64,
    pub(super) retained_bytes: u64,
}

pub(super) fn key_values_footprint_with_capacity(
    values: &[KeyValue],
    capacity: usize,
    limits: &ValueLimitSet,
) -> Result<KeyValuesFootprint, TraceReceiveFailure> {
    let attribute_limit =
        usize::try_from(limits.dynamic_value().attributes_per_namespace().value())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if values.len() > attribute_limit {
        return Err(TraceReceiveFailure::ValueLimitExceeded);
    }
    values.iter().try_fold(
        KeyValuesFootprint {
            wire_bytes: 0,
            retained_bytes: u64::try_from(capacity)
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                .checked_mul(WIRE_KEY_VALUE_SLOT_BYTES)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
        },
        |footprint, value| {
            let key_limit = usize::try_from(limits.dynamic_value().key_path_bytes().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.key.len() > key_limit {
                return Err(TraceReceiveFailure::ValueLimitExceeded);
            }
            let wire_bytes = footprint
                .wire_bytes
                .checked_add(
                    u64::try_from(value.encoded_len())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            let retained_bytes = footprint
                .retained_bytes
                .checked_add(key_value_retained_bytes(
                    value,
                    limits,
                    limits.dynamic_value().nesting_depth().value(),
                )?)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            Ok(KeyValuesFootprint {
                wire_bytes,
                retained_bytes,
            })
        },
    )
}

fn key_value_retained_bytes(
    value: &KeyValue,
    limits: &ValueLimitSet,
    remaining_depth: u16,
) -> Result<u64, TraceReceiveFailure> {
    let nested = value.value.as_ref().map_or(Ok(0), |value| {
        any_value_retained_bytes(value, limits, remaining_depth)
    })?;
    u64::try_from(value.key.capacity())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_add(WIRE_KEY_VALUE_SLOT_BYTES)
        .and_then(|bytes| bytes.checked_add(nested))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
}

pub(super) fn entity_refs_footprint(
    values: &[EntityRef],
    capacity: usize,
    limits: &ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    if values.len() > 1_024 {
        return Err(TraceReceiveFailure::ValueLimitExceeded);
    }
    let key_limit = usize::try_from(limits.dynamic_value().key_path_bytes().value())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let mut retained = u64::try_from(capacity)
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_mul(WIRE_ENTITY_REF_SLOT_BYTES)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    for entity in values {
        for text in [&entity.schema_url, &entity.r#type] {
            if text.len() > key_limit {
                return Err(TraceReceiveFailure::ValueLimitExceeded);
            }
            retained = retained
                .checked_add(
                    u64::try_from(text.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        }
        for keys in [&entity.id_keys, &entity.description_keys] {
            retained = retained
                .checked_add(
                    u64::try_from(keys.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                        .checked_mul(size_of::<String>() as u64)
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            for key in keys {
                if key.len() > key_limit {
                    return Err(TraceReceiveFailure::ValueLimitExceeded);
                }
                retained = retained
                    .checked_add(
                        u64::try_from(key.capacity())
                            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                    )
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            }
        }
    }
    Ok(retained)
}

pub(super) fn span_detail_retained_bytes(
    span: &Span,
    limits: &ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    let mut retained = u64::try_from(span.trace_state.capacity())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    if let Some(status) = &span.status {
        retained = retained
            .checked_add(
                u64::try_from(status.message.capacity())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    retained = retained
        .checked_add(
            u64::try_from(span.events.capacity())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                .checked_mul(WIRE_EVENT_SLOT_BYTES)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .and_then(|bytes| {
            u64::try_from(span.links.capacity())
                .ok()?
                .checked_mul(WIRE_LINK_SLOT_BYTES)
                .and_then(|links| bytes.checked_add(links))
        })
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    for event in &span.events {
        let attributes = key_values_footprint_with_capacity(
            &event.attributes,
            event.attributes.capacity(),
            limits,
        )?;
        retained = retained
            .checked_add(
                u64::try_from(event.name.capacity())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .and_then(|bytes| bytes.checked_add(attributes.retained_bytes))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    for link in &span.links {
        let attributes = key_values_footprint_with_capacity(
            &link.attributes,
            link.attributes.capacity(),
            limits,
        )?;
        retained = retained
            .checked_add(
                u64::try_from(link.trace_state.capacity())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .and_then(|bytes| bytes.checked_add(attributes.retained_bytes))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    Ok(retained)
}

fn any_value_retained_bytes(
    value: &AnyValue,
    limits: &ValueLimitSet,
    remaining_depth: u16,
) -> Result<u64, TraceReceiveFailure> {
    let mut retained = WIRE_ANY_VALUE_SLOT_BYTES;
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
            let entry_limit = usize::try_from(limits.dynamic_value().array_entries().value())
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.values.len() > entry_limit {
                return Err(TraceReceiveFailure::ValueLimitExceeded);
            }
            let next_depth = remaining_depth
                .checked_sub(1)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            retained = retained
                .checked_add(
                    u64::try_from(value.values.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                        .checked_mul(WIRE_ANY_VALUE_SLOT_BYTES)
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            for child in &value.values {
                retained = retained
                    .checked_add(any_value_retained_bytes(child, limits, next_depth)?)
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            }
        },
        Some(any_value::Value::KvlistValue(value)) => {
            let entry_limit =
                usize::try_from(limits.dynamic_value().key_value_list_entries().value())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
            if value.values.len() > entry_limit {
                return Err(TraceReceiveFailure::ValueLimitExceeded);
            }
            let next_depth = remaining_depth
                .checked_sub(1)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            retained = retained
                .checked_add(
                    u64::try_from(value.values.capacity())
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
                        .checked_mul(WIRE_KEY_VALUE_SLOT_BYTES)
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            for child in &value.values {
                retained = retained
                    .checked_add(key_value_retained_bytes(child, limits, next_depth)?)
                    .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
            }
        },
    }
    Ok(retained)
}
