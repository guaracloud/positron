use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans};
use positron_domain::value::ValueLimitProfile;
use positron_kernel::{ResourceAmounts, ResourceReservation};
use prost::Message;

use super::TraceReceiveFailure;

/// Checked pre-materialization accounting for resource/scope fan-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TraceFanoutFootprint {
    pub(super) aggregate_attributes: usize,
    pub(super) retained_bytes: u64,
}

pub(super) fn reserve_before_materialization<'authority>(
    resources: &[ResourceSpans],
    profile: ValueLimitProfile,
    capacity: Option<&mut ResourceReservation<'authority>>,
) -> Result<TraceFanoutFootprint, TraceReceiveFailure> {
    let limits = profile.system_limits();
    let maximum_attributes = usize::try_from(limits.request().aggregate_attributes().value())
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let maximum_decoded = limits.request().decompressed_bytes().value();
    let mut footprint = TraceFanoutFootprint {
        aggregate_attributes: 0,
        retained_bytes: 0,
    };
    for resource in resources {
        let resource_attributes = resource
            .resource
            .as_ref()
            .map_or(&[][..], |resource| resource.attributes.as_slice());
        let resource_bytes = key_values_bytes(resource_attributes)?;
        for scope in &resource.scope_spans {
            add_scope(
                &mut footprint,
                resource_attributes,
                resource_bytes,
                scope,
                maximum_attributes,
            )?;
        }
    }
    if footprint.retained_bytes > u64::from(maximum_decoded) {
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
    resource_bytes: u64,
    scope: &ScopeSpans,
    maximum_attributes: usize,
) -> Result<(), TraceReceiveFailure> {
    let scope_attributes = scope
        .scope
        .as_ref()
        .map_or(&[][..], |scope| scope.attributes.as_slice());
    let scope_bytes = key_values_bytes(scope_attributes)?;
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

    let metadata_component = u64::try_from(scope.schema_url.len().saturating_add(
        scope.scope.as_ref().map_or(0, |scope| {
            scope.name.len().saturating_add(scope.version.len())
        }),
    ))
    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
    let metadata_bytes = resource_bytes
        .checked_add(scope_bytes)
        .and_then(|bytes| bytes.checked_add(metadata_component))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let metadata_fanout = metadata_bytes
        .checked_mul(
            u64::try_from(span_count).map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
        )
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    let span_bytes = scope.spans.iter().try_fold(0_u64, |total, span| {
        let encoded = u64::try_from(span.encoded_len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        total
            .checked_add(encoded)
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })?;
    footprint.retained_bytes = footprint
        .retained_bytes
        .checked_add(metadata_fanout)
        .and_then(|bytes| bytes.checked_add(span_bytes))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
    Ok(())
}

fn key_values_bytes(values: &[KeyValue]) -> Result<u64, TraceReceiveFailure> {
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(
                u64::try_from(value.encoded_len())
                    .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
            )
            .ok_or(TraceReceiveFailure::ValueLimitExceeded)
    })
}
