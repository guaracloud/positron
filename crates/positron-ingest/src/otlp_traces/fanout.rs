use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{ResourceAmounts, ResourceReservation};
use prost::Message;
use std::mem::size_of;

use super::TraceReceiveFailure;

/// Checked pre-materialization accounting for resource/scope fan-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TraceFanoutFootprint {
    pub(super) aggregate_attributes: usize,
    pub(super) retained_bytes: u64,
}

const NATIVE_DRAFT_BYTES: u64 = size_of::<super::decoded::NativeSpanDraft>() as u64;
const NATIVE_OBSERVATION_BYTES: u64 = size_of::<positron_signals::SpanObservation>() as u64;
const DETAIL_EVENT_SLOT_BYTES: u64 = size_of::<positron_signals::SpanEvent>() as u64;
const DETAIL_LINK_SLOT_BYTES: u64 = size_of::<positron_signals::SpanLink>() as u64;
const ATTRIBUTE_SLOT_BYTES: u64 = 128;
const WIRE_KEY_VALUE_SLOT_BYTES: u64 = size_of::<KeyValue>() as u64;
const WIRE_ANY_VALUE_SLOT_BYTES: u64 = size_of::<AnyValue>() as u64;
const WIRE_EVENT_SLOT_BYTES: u64 = size_of::<Event>() as u64;
const WIRE_LINK_SLOT_BYTES: u64 = size_of::<Link>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyValuesFootprint {
    wire_bytes: u64,
    retained_bytes: u64,
}

pub(super) fn reserve_before_materialization<'authority>(
    resources: &[ResourceSpans],
    profile: ValueLimitProfile,
    policy: &positron_policy::IngestPolicy,
    capacity: Option<&mut ResourceReservation<'authority>>,
) -> Result<TraceFanoutFootprint, TraceReceiveFailure> {
    let limits = profile.effective_limits();
    let maximum_attributes = usize::try_from(limits.request().aggregate_attributes().value())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let maximum_decoded = super::MAX_RETAINED_BYTES;
    let mut footprint = TraceFanoutFootprint {
        aggregate_attributes: 0,
        retained_bytes: 0,
    };
    for resource in resources {
        let resource_attributes = resource
            .resource
            .as_ref()
            .map_or(&[][..], |resource| resource.attributes.as_slice());
        let resource_bytes = key_values_footprint(resource_attributes, &limits)?;
        for scope in &resource.scope_spans {
            add_scope(
                &mut footprint,
                resource_attributes,
                resource_bytes,
                resource.schema_url.capacity(),
                scope,
                maximum_attributes,
                &limits,
            )?;
        }
    }
    // Policy evaluation is pinned once for this request. Its canonical budget
    // covers shared scratch and the worst retained provenance/rule strings;
    // native per-span provenance is charged again by the exact post-policy
    // observation accounting before the reservation is resized.
    footprint.retained_bytes = footprint
        .retained_bytes
        .checked_add(
            policy
                .budget()
                .reserved_memory_bytes()
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    if footprint.retained_bytes > maximum_decoded {
        return Err(TraceReceiveFailure::ValueLimitExceeded);
    }
    if let Some(capacity) = capacity {
        let amounts =
            ResourceAmounts::new([footprint.retained_bytes, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0]);
        capacity
            .try_resize(amounts)
            .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
    }
    Ok(footprint)
}

fn add_scope(
    footprint: &mut TraceFanoutFootprint,
    resource_attributes: &[KeyValue],
    resource_bytes: KeyValuesFootprint,
    resource_schema_url_capacity: usize,
    scope: &ScopeSpans,
    maximum_attributes: usize,
    limits: &positron_domain::value::ValueLimitSet,
) -> Result<(), TraceReceiveFailure> {
    let scope_attributes = scope
        .scope
        .as_ref()
        .map_or(&[][..], |scope| scope.attributes.as_slice());
    let scope_bytes = key_values_footprint(scope_attributes, limits)?;
    let span_count = scope.spans.len();
    let fanout_attributes = resource_attributes
        .len()
        .checked_add(scope_attributes.len())
        .and_then(|count| count.checked_mul(span_count))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let span_attributes = scope.spans.iter().try_fold(0_usize, |total, span| {
        total
            .checked_add(span.attributes.len())
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })?;
    footprint.aggregate_attributes = footprint
        .aggregate_attributes
        .checked_add(fanout_attributes)
        .and_then(|count| count.checked_add(span_attributes))
        .filter(|count| *count <= maximum_attributes)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;

    let scope_metadata_bytes = scope.scope.as_ref().map_or(Ok(0_usize), |scope| {
        scope
            .name
            .capacity()
            .checked_add(scope.version.capacity())
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })?;
    let metadata_component = scope
        .schema_url
        .capacity()
        .checked_add(scope_metadata_bytes)
        .and_then(|bytes| bytes.checked_add(resource_schema_url_capacity))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
        .and_then(|value| {
            u64::try_from(value).map_err(|_| TraceReceiveFailure::ValueLimitExceeded)
        })?;
    let metadata_bytes = resource_bytes
        .wire_bytes
        .checked_add(resource_bytes.retained_bytes)
        .and_then(|bytes| bytes.checked_add(scope_bytes.wire_bytes))
        .and_then(|bytes| bytes.checked_add(scope_bytes.retained_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_component))
        .and_then(|bytes| {
            let attribute_count = resource_attributes
                .len()
                .checked_add(scope_attributes.len())?;
            u64::try_from(attribute_count)
                .ok()?
                .checked_mul(ATTRIBUTE_SLOT_BYTES)
                .and_then(|slots| {
                    bytes.checked_add(slots).and_then(|bytes| {
                        u64::try_from(
                            size_of::<positron_signals::SpanResourceMetadata>()
                                .checked_add(size_of::<positron_signals::SpanScopeMetadata>())?,
                        )
                        .ok()
                        .and_then(|metadata| bytes.checked_add(metadata))
                    })
                })
        })
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let metadata_fanout = metadata_bytes
        .checked_mul(
            u64::try_from(span_count).map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let span_bytes = scope.spans.iter().try_fold(0_u64, |total, span| {
        let encoded = u64::try_from(span.encoded_len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let detail_memory = span_detail_footprint(span, limits)?;
        let span_attributes = key_values_footprint(&span.attributes, limits)?;
        let detail_slots = u64::try_from(span.events.len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
            .checked_mul(DETAIL_EVENT_SLOT_BYTES)
            .and_then(|events| {
                u64::try_from(span.links.len())
                    .ok()?
                    .checked_mul(DETAIL_LINK_SLOT_BYTES)
                    .and_then(|links| events.checked_add(links))
            })
            .and_then(|slots| {
                u64::try_from(span.attributes.len())
                    .ok()?
                    .checked_mul(ATTRIBUTE_SLOT_BYTES)
                    .and_then(|attributes| slots.checked_add(attributes))
            })
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        let native_slots = NATIVE_DRAFT_BYTES
            .checked_add(NATIVE_OBSERVATION_BYTES)
            .and_then(|bytes| bytes.checked_add(detail_slots))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        total
            .checked_add(encoded)
            .and_then(|bytes| bytes.checked_add(span_attributes.retained_bytes))
            .and_then(|bytes| bytes.checked_add(detail_memory))
            .and_then(|bytes| bytes.checked_add(native_slots))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })?;
    footprint.retained_bytes = footprint
        .retained_bytes
        .checked_add(metadata_fanout)
        .and_then(|bytes| bytes.checked_add(span_bytes))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    Ok(())
}

fn key_values_footprint(
    values: &[KeyValue],
    limits: &positron_domain::value::ValueLimitSet,
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
            retained_bytes: 0,
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
    limits: &positron_domain::value::ValueLimitSet,
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

fn any_value_retained_bytes(
    value: &AnyValue,
    limits: &positron_domain::value::ValueLimitSet,
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

fn span_detail_footprint(
    span: &Span,
    limits: &positron_domain::value::ValueLimitSet,
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
        retained = retained
            .checked_add(
                u64::try_from(event.name.capacity())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    key_values_footprint(&event.attributes, limits)
                        .ok()?
                        .retained_bytes,
                )
            })
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    for link in &span.links {
        retained = retained
            .checked_add(
                u64::try_from(link.trace_state.capacity())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    key_values_footprint(&link.attributes, limits)
                        .ok()?
                        .retained_bytes,
                )
            })
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    }
    Ok(retained)
}
