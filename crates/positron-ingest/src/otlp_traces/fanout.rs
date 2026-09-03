use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{ResourceAmounts, ResourceReservation};
use prost::Message;
use std::mem::size_of;

use super::TraceReceiveFailure;

mod native;
mod wire;

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
const ATTRIBUTE_SLOT_BYTES: u64 =
    size_of::<positron_domain::value::AttributeOccurrenceSet>() as u64;

struct ResourceFootprint<'resource> {
    attributes: &'resource [KeyValue],
    attribute_capacity: usize,
    bytes: wire::KeyValuesFootprint,
    native_bytes: u64,
    schema_url_capacity: usize,
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
        let resource_attribute_capacity = resource
            .resource
            .as_ref()
            .map_or(0, |resource| resource.attributes.capacity());
        let resource_bytes = wire::key_values_footprint_with_capacity(
            resource_attributes,
            resource_attribute_capacity,
            &limits,
        )?;
        let resource_native_bytes = native::key_values_bytes(resource_attributes, &limits)?;
        let resource_footprint = ResourceFootprint {
            attributes: resource_attributes,
            attribute_capacity: resource_attribute_capacity,
            bytes: resource_bytes,
            native_bytes: resource_native_bytes,
            schema_url_capacity: resource.schema_url.capacity(),
        };
        let entity_refs = resource
            .resource
            .as_ref()
            .map_or(&[][..], |resource| resource.entity_refs.as_slice());
        let entity_ref_capacity = resource
            .resource
            .as_ref()
            .map_or(0, |resource| resource.entity_refs.capacity());
        footprint.retained_bytes = footprint
            .retained_bytes
            .checked_add(wire::entity_refs_footprint(
                entity_refs,
                entity_ref_capacity,
                &limits,
            )?)
            .and_then(|bytes| {
                u64::try_from(resource.scope_spans.capacity())
                    .ok()?
                    .checked_mul(size_of::<ScopeSpans>() as u64)
                    .and_then(|scope_slots| bytes.checked_add(scope_slots))
            })
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
        for scope in &resource.scope_spans {
            add_scope(
                &mut footprint,
                &resource_footprint,
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

fn span_detail_footprint(
    span: &Span,
    limits: &positron_domain::value::ValueLimitSet,
) -> Result<u64, TraceReceiveFailure> {
    let wire_bytes = wire::span_detail_retained_bytes(span, limits)?;
    let native_bytes = native::span_detail_bytes(span, limits)?;
    wire_bytes
        .checked_add(native_bytes)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
}

fn add_scope(
    footprint: &mut TraceFanoutFootprint,
    resource: &ResourceFootprint<'_>,
    scope: &ScopeSpans,
    maximum_attributes: usize,
    limits: &positron_domain::value::ValueLimitSet,
) -> Result<(), TraceReceiveFailure> {
    let scope_attributes = scope
        .scope
        .as_ref()
        .map_or(&[][..], |scope| scope.attributes.as_slice());
    let scope_attribute_capacity = scope
        .scope
        .as_ref()
        .map_or(0, |scope| scope.attributes.capacity());
    let scope_bytes = wire::key_values_footprint_with_capacity(
        scope_attributes,
        scope_attribute_capacity,
        limits,
    )?;
    let scope_native_bytes = native::key_values_bytes(scope_attributes, limits)?;
    let span_count = scope.spans.len();
    let fanout_attributes = resource
        .attributes
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
        .and_then(|bytes| bytes.checked_add(resource.schema_url_capacity))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
        .and_then(|value| {
            u64::try_from(value).map_err(|_| TraceReceiveFailure::ValueLimitExceeded)
        })?;
    let shared_metadata_bytes = resource
        .bytes
        .wire_bytes
        .checked_add(resource.bytes.retained_bytes)
        .and_then(|bytes| bytes.checked_add(scope_bytes.wire_bytes))
        .and_then(|bytes| bytes.checked_add(scope_bytes.retained_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_component))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let attribute_count = resource
        .attributes
        .len()
        .checked_add(scope_attributes.len())
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let attribute_capacity = resource
        .attribute_capacity
        .checked_add(scope_attribute_capacity)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let attribute_slots = u64::try_from(attribute_count)
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_mul(ATTRIBUTE_SLOT_BYTES)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let capacity_slots = u64::try_from(attribute_capacity)
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_mul(ATTRIBUTE_SLOT_BYTES)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let metadata_struct_bytes = u64::try_from(
        size_of::<positron_signals::SpanResourceMetadata>()
            .checked_add(size_of::<positron_signals::SpanScopeMetadata>())
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
    )
    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let native_metadata_bytes = resource
        .native_bytes
        .checked_add(scope_native_bytes)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let per_span_metadata_bytes = attribute_slots
        .checked_add(capacity_slots)
        .and_then(|bytes| bytes.checked_add(metadata_struct_bytes))
        .and_then(|bytes| bytes.checked_add(metadata_component))
        .and_then(|bytes| bytes.checked_add(native_metadata_bytes))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let metadata_fanout = shared_metadata_bytes
        .checked_add(
            per_span_metadata_bytes
                .checked_mul(
                    u64::try_from(span_count)
                        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                )
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let span_bytes = scope.spans.iter().try_fold(0_u64, |total, span| {
        let encoded = u64::try_from(span.encoded_len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let detail_memory = span_detail_footprint(span, limits)?;
        let span_attributes = wire::key_values_footprint_with_capacity(
            &span.attributes,
            span.attributes.capacity(),
            limits,
        )?;
        let span_native_bytes = native::key_values_bytes(&span.attributes, limits)?;
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
            .and_then(|bytes| bytes.checked_add(span_native_bytes))
            .and_then(|bytes| bytes.checked_add(detail_memory))
            .and_then(|bytes| bytes.checked_add(native_slots))
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })?;
    let span_vector_bytes = u64::try_from(scope.spans.capacity())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?
        .checked_mul(size_of::<Span>() as u64)
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    footprint.retained_bytes = footprint
        .retained_bytes
        .checked_add(metadata_fanout)
        .and_then(|bytes| bytes.checked_add(span_vector_bytes))
        .and_then(|bytes| bytes.checked_add(span_bytes))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    Ok(())
}
