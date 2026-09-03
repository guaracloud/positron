use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use positron_domain::value::ValueLimitProfile;
use prost::Message;

use super::{
    NativeSpanBatch, TraceReceiveFailure, bounds, decoded, fanout, increment_rejection, request,
    transport,
};

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
        request: super::AuthenticatedOtlpTracesRequest<'authority>,
    ) -> Result<NativeSpanBatch<'authority>, TraceReceiveFailure> {
        let policy = positron_policy::IngestPolicy::preserving(1)
            .map_err(|_| TraceReceiveFailure::MalformedPayload)?;
        self.decode_with_policy(request, &policy)
    }

    pub fn decode_with_policy<'authority>(
        &self,
        request: super::AuthenticatedOtlpTracesRequest<'authority>,
        policy: &positron_policy::IngestPolicy,
    ) -> Result<NativeSpanBatch<'authority>, TraceReceiveFailure> {
        let super::AuthenticatedOtlpTracesRequest {
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
            policy,
            capacity.as_mut(),
        )?;
        let (drafts, mut rejections) = decoded::native_records(decoded, &self.value_limit_profile)?;
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
            match draft.evaluate(policy, receiver, &self.value_limit_profile) {
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
                Err(TraceReceiveFailure::PolicyEvaluationFailed) => {
                    return Err(TraceReceiveFailure::PolicyEvaluationFailed);
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
