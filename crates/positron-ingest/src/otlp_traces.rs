//! OTLP Trace Receiver Adapter.
//!
//! This module is deliberately limited to protocol decoding and the handoff
//! to the receiver-independent Trace ingest path. Authentication and
//! durability remain owned by the runtime and Storage Kernel respectively.

use positron_domain::identity::TenantAttribution;
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ResourceAmounts, ResourceGovernor, ResourceReservation, WorkClaim, WorkKind,
};

mod admission_groups;
mod batch;
mod bounds;
mod decoded;
#[cfg(test)]
mod detail_boundaries;
mod failure;
mod fanout;
#[cfg(test)]
mod fanout_boundaries;
#[cfg(test)]
mod grammar_boundaries;
#[cfg(test)]
mod json_boundaries;
#[cfg(test)]
mod mapping_matrix;
#[cfg(test)]
mod policy_boundaries;
#[cfg(test)]
mod protocol_matrix;
mod receiver;
mod request;
#[cfg(test)]
mod semantic_rejections;
#[cfg(test)]
mod structural_bounds;
mod transport;

pub use admission_groups::{NativeSpanAdmissionGroup, NativeSpanAdmissionGroups};
pub use batch::NativeSpanBatch;
pub use failure::TraceReceiveFailure;
pub use receiver::OtlpTracesReceiver;
pub use request::{AuthenticatedOtlpTracesRequest, OtlpTracesRequestEncoding};

pub(super) const MAX_RETAINED_BYTES: u64 = 4_194_304;
const MAX_RECORDS: u64 = 1_024;
const RECEIVER_CAPACITY: ResourceAmounts = ResourceAmounts::new([
    MAX_RETAINED_BYTES,
    1,
    1,
    1_048_576,
    MAX_RECORDS,
    0,
    0,
    0,
    1,
    1,
    0,
]);

/// Reserves the canonical Trace receiver budget after authentication and
/// before structural protocol decoding.
pub fn reserve_trace_receiver_transport<'authority>(
    context: AuthorizedContext,
    governor: ResourceGovernor<'authority>,
) -> Result<ResourceReservation<'authority>, TraceReceiveFailure> {
    let attribution = ingest_attribution(context)?;
    let claim = WorkClaim::tenant(attribution.tenant_id(), WorkKind::Ingest, RECEIVER_CAPACITY)
        .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
    governor
        .reserve(claim)
        .map_err(|_| TraceReceiveFailure::CapacityUnavailable)
}

pub(crate) fn ingest_attribution(
    context: AuthorizedContext,
) -> Result<TenantAttribution, TraceReceiveFailure> {
    context
        .tenant_attribution()
        .filter(|attribution| attribution.scope() == positron_domain::identity::Scope::Ingest)
        .ok_or(TraceReceiveFailure::AuthenticationRejected)
}

/// Validates the Release 1 OTLP Traces protobuf shape before materializing it.
pub fn preflight_otlp_traces_protobuf(protobuf: &[u8]) -> Result<(), TraceReceiveFailure> {
    bounds::validate_protobuf(
        protobuf,
        positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
    )
}

/// Validates the Release 1 OTLP Traces ProtoJSON shape before materializing it.
pub fn preflight_otlp_traces_json(json: &[u8]) -> Result<(), TraceReceiveFailure> {
    bounds::validate_json(
        json,
        positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
    )
}

/// Runs the bounded gzip and protocol preflight used by the HTTP receiver.
/// The selector only chooses the wire representation; it does not bypass
/// authentication or admission, which remain runtime-owned at ingestion.
pub fn preflight_otlp_traces_gzip(gzip: &[u8], json: bool) -> Result<(), TraceReceiveFailure> {
    let payload = if json {
        request::OtlpPayload::GzipJson(gzip.to_vec())
    } else {
        request::OtlpPayload::GzipProtobuf(gzip.to_vec())
    };
    match transport::bounded_payload(
        payload,
        positron_domain::value::ValueLimitProfile::release_1_system_maximum(),
    )? {
        transport::BoundedOtlpPayload::Protobuf(protobuf) => {
            preflight_otlp_traces_protobuf(&protobuf)
        },
        transport::BoundedOtlpPayload::Json(json) => preflight_otlp_traces_json(&json),
    }
}

/// Fuzz entrypoint for the authenticated receiver's bounded protocol seam.
/// The synthetic attribution is only a fuzz fixture; production callers must
/// obtain attribution from the governance identity boundary.
#[cfg(fuzzing)]
pub fn fuzz_otlp_traces(data: &[u8]) {
    let Some(selector) = data.first() else {
        return;
    };
    let Some(principal) = positron_domain::identity::PrincipalId::from_bytes([1; 16]).ok() else {
        return;
    };
    let Some(tenant) = positron_domain::identity::TenantId::from_bytes([2; 16]).ok() else {
        return;
    };
    let Ok(attribution) =
        TenantAttribution::new(principal, positron_domain::identity::Scope::Ingest, tenant)
    else {
        return;
    };
    let bytes = data.get(1..).unwrap_or_default().to_vec();
    let payload = match selector & 3 {
        0 => request::OtlpPayload::Protobuf(bytes),
        1 => request::OtlpPayload::Json(bytes),
        2 => request::OtlpPayload::GzipProtobuf(bytes),
        _ => request::OtlpPayload::GzipJson(bytes),
    };
    let request = request::AuthenticatedOtlpTracesRequest {
        attribution,
        payload,
        capacity: None,
        receiver: crate::PolicyReceiver::OtlpGrpc,
    };
    let _ = OtlpTracesReceiver::new().decode(request);
}

pub(crate) fn checked_identifier<const N: usize>(
    value: &[u8],
) -> Result<[u8; N], TraceReceiveFailure> {
    let identifier: [u8; N] = value
        .try_into()
        .map_err(|_| TraceReceiveFailure::MalformedPayload)?;
    if identifier.iter().all(|byte| *byte == 0) {
        return Err(TraceReceiveFailure::MalformedPayload);
    }
    Ok(identifier)
}

pub(crate) fn checked_timestamp(value: u64) -> Result<i64, TraceReceiveFailure> {
    i64::try_from(value).map_err(|_| TraceReceiveFailure::TimestampOutOfRange)
}

pub(crate) fn map_store_failure(
    failure: positron_signals::TraceStoreFailure,
) -> TraceReceiveFailure {
    match failure.code() {
        positron_signals::TraceStoreFailureCode::LimitExceeded => {
            TraceReceiveFailure::ValueLimitExceeded
        },
        positron_signals::TraceStoreFailureCode::ResourceExhausted => {
            TraceReceiveFailure::CapacityUnavailable
        },
        _ => TraceReceiveFailure::MalformedPayload,
    }
}

pub(crate) fn increment_rejection(counts: &mut [usize; 3], code: crate::IngestFailureCode) {
    let index = match code {
        crate::IngestFailureCode::PolicyRejected => 0,
        crate::IngestFailureCode::InvalidRecord => 1,
        crate::IngestFailureCode::ValueLimitExceeded => 2,
        _ => return,
    };
    if let Some(count) = counts.get_mut(index) {
        *count = count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests;
