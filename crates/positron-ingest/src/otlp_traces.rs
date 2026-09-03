//! OTLP Trace Receiver Adapter.
//!
//! This module is deliberately limited to protocol decoding and the handoff
//! to the receiver-independent Trace ingest path.  Authentication and
//! durability remain owned by the runtime and Storage Kernel respectively.

use std::fmt::{Display, Formatter};

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use positron_governance::AuthorizedContext;
use positron_kernel::{
    ResourceAmounts, ResourceGovernor, ResourceReservation, WorkClaim, WorkKind,
};
use positron_signals::SpanObservation;
use prost::Message;

mod admission_groups;
mod bounds;
mod decoded;
#[cfg(test)]
mod detail_boundaries;
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
mod request;
#[cfg(test)]
mod semantic_rejections;
#[cfg(test)]
mod structural_bounds;
mod transport;

pub use admission_groups::{NativeSpanAdmissionGroup, NativeSpanAdmissionGroups};
pub use request::{AuthenticatedOtlpTracesRequest, OtlpTracesRequestEncoding};

const MAX_RETAINED_BYTES: u64 = 4_194_304;
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

/// Stable receiver-side rejection classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceReceiveFailure {
    AuthenticationRejected,
    CapacityUnavailable,
    MalformedPayload,
    MalformedCompression,
    TransportLimitExceeded,
    ValueLimitExceeded,
    TimestampOutOfRange,
    UnsupportedValue,
}

impl Display for TraceReceiveFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OTLP Traces request was rejected")
    }
}

impl std::error::Error for TraceReceiveFailure {}

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

/// One tenant-bound native span batch after protocol mapping.
#[derive(Debug)]
pub struct NativeSpanBatch<'authority> {
    attribution: TenantAttribution,
    records: Vec<SpanObservation>,
    rejections: [usize; 3],
    value_limit_profile: ValueLimitProfile,
    decoded_bytes: u64,
    capacity: Option<ResourceReservation<'authority>>,
    receiver: crate::PolicyReceiver,
}

impl<'authority> NativeSpanBatch<'authority> {
    #[cfg(test)]
    pub(crate) fn new(
        attribution: TenantAttribution,
        records: Vec<SpanObservation>,
        value_limit_profile: ValueLimitProfile,
        decoded_bytes: u64,
        capacity: Option<ResourceReservation<'authority>>,
        receiver: crate::PolicyReceiver,
    ) -> Result<Self, TraceReceiveFailure> {
        Self::new_with_rejections(
            attribution,
            records,
            value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
            [0; 3],
        )
    }

    pub(crate) fn new_with_rejections(
        attribution: TenantAttribution,
        records: Vec<SpanObservation>,
        value_limit_profile: ValueLimitProfile,
        decoded_bytes: u64,
        capacity: Option<ResourceReservation<'authority>>,
        receiver: crate::PolicyReceiver,
        rejections: [usize; 3],
    ) -> Result<Self, TraceReceiveFailure> {
        let mut batch = Self {
            attribution,
            records,
            rejections,
            value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
        };
        batch.resize_after_decode()?;
        Ok(batch)
    }

    #[must_use]
    pub const fn attribution(&self) -> TenantAttribution {
        self.attribution
    }

    #[must_use]
    pub fn records(&self) -> &[SpanObservation] {
        &self.records
    }

    #[must_use]
    pub(crate) const fn rejections(&self) -> [usize; 3] {
        self.rejections
    }

    #[must_use]
    pub const fn value_limit_profile(&self) -> ValueLimitProfile {
        self.value_limit_profile
    }

    #[must_use]
    pub const fn receiver(&self) -> crate::PolicyReceiver {
        self.receiver
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        TenantAttribution,
        Vec<SpanObservation>,
        ValueLimitProfile,
        Option<ResourceReservation<'authority>>,
        crate::PolicyReceiver,
    ) {
        (
            self.attribution,
            self.records,
            self.value_limit_profile,
            self.capacity,
            self.receiver,
        )
    }

    pub fn with_policy_provenance(
        self,
        policy: positron_policy::PolicyProvenance,
    ) -> Result<Self, TraceReceiveFailure> {
        let Self {
            attribution,
            records,
            rejections,
            value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
        } = self;
        let mut rebound = Vec::new();
        rebound
            .try_reserve_exact(records.len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        for record in records {
            rebound.push(
                record
                    .with_policy_provenance(policy.clone())
                    .map_err(|failure| match failure.code() {
                        positron_signals::TraceStoreFailureCode::LimitExceeded => {
                            TraceReceiveFailure::ValueLimitExceeded
                        },
                        _ => TraceReceiveFailure::MalformedPayload,
                    })?,
            );
        }
        Ok(Self {
            attribution,
            records: rebound,
            rejections,
            value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
        })
    }

    fn resize_after_decode(&mut self) -> Result<(), TraceReceiveFailure> {
        let record_count = u64::try_from(self.records.len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let retained_peak = bounds::retained_batch_bytes(self.decoded_bytes, self.records.len())?;
        if retained_peak > MAX_RETAINED_BYTES {
            return Err(TraceReceiveFailure::ValueLimitExceeded);
        }
        let amounts =
            ResourceAmounts::new([retained_peak, 1, 1, 0, record_count, 0, 0, 0, 1, 1, 0]);
        if let Some(capacity) = self.capacity.as_mut() {
            capacity
                .try_resize(amounts)
                .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
        }
        Ok(())
    }
}

/// OTLP Trace Receiver Adapter for protobuf and ProtoJSON payloads.
#[derive(Clone, Copy, Debug)]
pub struct OtlpTracesReceiver {
    value_limit_profile: ValueLimitProfile,
}

impl Default for OtlpTracesReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl OtlpTracesReceiver {
    #[must_use]
    pub const fn new() -> Self {
        Self::with_value_limit_profile(ValueLimitProfile::release_1_system_maximum())
    }

    #[must_use]
    pub const fn with_value_limit_profile(value_limit_profile: ValueLimitProfile) -> Self {
        Self {
            value_limit_profile,
        }
    }

    pub fn decode<'authority>(
        &self,
        request: AuthenticatedOtlpTracesRequest<'authority>,
    ) -> Result<NativeSpanBatch<'authority>, TraceReceiveFailure> {
        let policy = positron_policy::IngestPolicy::preserving(1)
            .map_err(|_| TraceReceiveFailure::MalformedPayload)?;
        self.decode_with_policy(request, &policy)
    }

    pub fn decode_with_policy<'authority>(
        &self,
        request: AuthenticatedOtlpTracesRequest<'authority>,
        policy: &positron_policy::IngestPolicy,
    ) -> Result<NativeSpanBatch<'authority>, TraceReceiveFailure> {
        let AuthenticatedOtlpTracesRequest {
            attribution,
            payload,
            mut capacity,
            receiver,
        } = request;
        let decoded = match payload {
            request::OtlpPayload::Decoded(decoded) => *decoded,
            encoded => match transport::bounded_payload(encoded, self.value_limit_profile)? {
                transport::BoundedOtlpPayload::Protobuf(protobuf) => {
                    bounds::validate_protobuf(&protobuf, self.value_limit_profile)?;
                    ExportTraceServiceRequest::decode(protobuf.as_slice())
                        .map_err(|_| TraceReceiveFailure::MalformedPayload)?
                },
                transport::BoundedOtlpPayload::Json(json) => {
                    bounds::validate_json(&json, self.value_limit_profile)?;
                    serde_json::from_slice(&json)
                        .map_err(|_| TraceReceiveFailure::MalformedPayload)?
                },
            },
        };
        fanout::reserve_before_materialization(
            &decoded.resource_spans,
            self.value_limit_profile,
            capacity.as_mut(),
        )?;
        let (drafts, mut rejections) = decoded::native_records(decoded, self.value_limit_profile)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(drafts.len())
            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let maximum_attributes = usize::try_from(
            self.value_limit_profile
                .effective_limits()
                .request()
                .aggregate_attributes()
                .value(),
        )
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let mut aggregate_attributes = 0_usize;
        let mut decoded_bytes = 0_u64;
        for draft in drafts {
            let estimated_bytes = draft.estimated_bytes();
            match draft.evaluate(policy, receiver, self.value_limit_profile) {
                Ok(Some(record)) => {
                    let record_attributes = record
                        .attributes()
                        .iter()
                        .try_fold(0_usize, |total, attribute| {
                            total.checked_add(attribute.len())
                        });
                    if let Some(total) = record_attributes
                        .and_then(|count| aggregate_attributes.checked_add(count))
                        .filter(|count| *count <= maximum_attributes)
                    {
                        aggregate_attributes = total;
                        decoded_bytes = decoded_bytes
                            .checked_add(estimated_bytes)
                            .ok_or(TraceReceiveFailure::ValueLimitExceeded)?;
                        records.push(record);
                    } else {
                        increment_rejection(
                            &mut rejections,
                            crate::IngestFailureCode::ValueLimitExceeded,
                        );
                    }
                },
                Ok(None) => {
                    increment_rejection(&mut rejections, crate::IngestFailureCode::PolicyRejected)
                },
                Err(TraceReceiveFailure::CapacityUnavailable) => {
                    return Err(TraceReceiveFailure::CapacityUnavailable);
                },
                Err(TraceReceiveFailure::ValueLimitExceeded) => increment_rejection(
                    &mut rejections,
                    crate::IngestFailureCode::ValueLimitExceeded,
                ),
                Err(_) => {
                    increment_rejection(&mut rejections, crate::IngestFailureCode::InvalidRecord)
                },
            }
        }
        NativeSpanBatch::new_with_rejections(
            attribution,
            records,
            self.value_limit_profile,
            decoded_bytes,
            capacity,
            receiver,
            rejections,
        )
    }
}

/// Validates the Release 1 OTLP Traces protobuf shape before materializing it.
pub fn preflight_otlp_traces_protobuf(protobuf: &[u8]) -> Result<(), TraceReceiveFailure> {
    bounds::validate_protobuf(protobuf, ValueLimitProfile::release_1_system_maximum())
}

/// Validates the Release 1 OTLP Traces ProtoJSON shape before materializing it.
pub fn preflight_otlp_traces_json(json: &[u8]) -> Result<(), TraceReceiveFailure> {
    bounds::validate_json(json, ValueLimitProfile::release_1_system_maximum())
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
    match transport::bounded_payload(payload, ValueLimitProfile::release_1_system_maximum())? {
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
    let request = AuthenticatedOtlpTracesRequest {
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
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::span::{Event, Link};
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
    use positron_signals::{SamplingDecision, SpanKind, SpanStatusCode};

    fn attribution() -> TenantAttribution {
        TenantAttribution::new(
            positron_domain::identity::PrincipalId::from_bytes([1; 16]).expect("principal"),
            positron_domain::identity::Scope::Ingest,
            positron_domain::identity::TenantId::from_bytes([2; 16]).expect("tenant"),
        )
        .expect("attribution")
    }

    #[test]
    fn protobuf_receiver_maps_resource_scope_and_span_values() {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_owned(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("checkout".to_owned())),
                        }),
                        ..KeyValue::default()
                    }],
                    dropped_attributes_count: 0,
                    ..Resource::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(
                        opentelemetry_proto::tonic::common::v1::InstrumentationScope {
                            name: "otel".to_owned(),
                            version: "1".to_owned(),
                            attributes: Vec::new(),
                            ..Default::default()
                        },
                    ),
                    spans: vec![Span {
                        trace_id: vec![0x11; 16],
                        span_id: vec![0x22; 8],
                        name: "checkout".to_owned(),
                        start_time_unix_nano: 10,
                        end_time_unix_nano: 20,
                        kind: 2,
                        flags: 1,
                        trace_state: "vendor=span".to_owned(),
                        status: Some(Status {
                            code: 2,
                            message: "upstream failed".to_owned(),
                        }),
                        events: vec![Event {
                            time_unix_nano: 15,
                            name: "cache.miss".to_owned(),
                            dropped_attributes_count: 3,
                            ..Event::default()
                        }],
                        links: vec![Link {
                            trace_id: vec![0x33; 16],
                            span_id: vec![0x44; 8],
                            trace_state: "vendor=link".to_owned(),
                            flags: 0x0402,
                            dropped_attributes_count: 4,
                            ..Link::default()
                        }],
                        dropped_attributes_count: 5,
                        dropped_events_count: 6,
                        dropped_links_count: 7,
                        ..Span::default()
                    }],
                    schema_url: "https://example.test/scope".to_owned(),
                }],
                schema_url: "https://example.test/resource".to_owned(),
            }],
        };
        let payload = request.encode_to_vec();
        let batch = OtlpTracesReceiver::new()
            .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                attribution(),
                payload,
            ))
            .expect("trace payload should decode");
        assert_eq!(batch.records().len(), 1);
        let record = batch.records().first().expect("one span");
        assert_eq!(record.trace_id(), [0x11; 16]);
        assert_eq!(record.span_id(), [0x22; 8]);
        assert_eq!(record.kind(), SpanKind::Server);
        assert_eq!(record.sampling(), SamplingDecision::Sampled);
        assert_eq!(record.attributes().len(), 1);
        assert_eq!(
            record.attributes()[0].namespace(),
            positron_domain::value::AttributeNamespace::Resource
        );
        assert_eq!(record.attributes()[0].key(), "service.name");
        let details = record.details();
        assert_eq!(details.trace_state(), "vendor=span");
        assert_eq!(details.flags(), 1);
        assert_eq!(details.status().code(), SpanStatusCode::Error);
        assert_eq!(details.status().message(), "upstream failed");
        assert_eq!(details.events().len(), 1);
        assert_eq!(details.events()[0].name(), "cache.miss");
        assert_eq!(details.events()[0].dropped_attributes_count(), 3);
        assert_eq!(details.links().len(), 1);
        assert_eq!(details.links()[0].trace_id(), [0x33; 16]);
        assert_eq!(details.links()[0].flags(), 0x0402);
        assert_eq!(details.dropped_attributes_count(), 5);
        assert_eq!(details.dropped_events_count(), 6);
        assert_eq!(details.dropped_links_count(), 7);
        assert_eq!(
            details.resource().schema_url(),
            "https://example.test/resource"
        );
        assert_eq!(details.scope().name(), "otel");
        assert_eq!(details.scope().version(), "1");
        assert_eq!(details.scope().schema_url(), "https://example.test/scope");
        assert_eq!(details.scope().dropped_attributes_count(), 0);
    }

    #[test]
    fn receiver_rejects_zero_or_wrong_width_span_ids() {
        for id in [vec![0; 16], vec![1; 15]] {
            let request = ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans {
                    resource: None,
                    scope_spans: vec![ScopeSpans {
                        scope: None,
                        spans: vec![Span {
                            trace_id: id,
                            span_id: vec![2; 8],
                            name: "invalid".to_owned(),
                            ..Span::default()
                        }],
                        schema_url: String::new(),
                    }],
                    schema_url: String::new(),
                }],
            };
            let batch = OtlpTracesReceiver::new()
                .decode(AuthenticatedOtlpTracesRequest::test_only_protobuf(
                    attribution(),
                    request.encode_to_vec(),
                ))
                .expect("invalid identifier is a per-span rejection");
            assert_eq!(batch.rejections(), [0, 1, 0]);
        }
    }

    #[test]
    fn json_receiver_uses_streamed_bounds_before_message_materialization() {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        trace_id: vec![0x11; 16],
                        span_id: vec![0x22; 8],
                        name: "checkout".to_owned(),
                        ..Span::default()
                    }],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            }],
        };
        let json = serde_json::to_vec(&request).expect("ProtoJSON encoding");
        let batch = OtlpTracesReceiver::new()
            .decode(AuthenticatedOtlpTracesRequest::test_only_json(
                attribution(),
                json,
            ))
            .expect("valid ProtoJSON payload");
        assert_eq!(batch.records().len(), 1);

        let oversized = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span::default(); 1_025],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            }],
        };
        let failure = OtlpTracesReceiver::new()
            .decode(AuthenticatedOtlpTracesRequest::test_only_json(
                attribution(),
                serde_json::to_vec(&oversized).expect("ProtoJSON encoding"),
            ))
            .expect_err("JSON record bound must fail before allocation");
        assert_eq!(failure, TraceReceiveFailure::ValueLimitExceeded);
    }
}
