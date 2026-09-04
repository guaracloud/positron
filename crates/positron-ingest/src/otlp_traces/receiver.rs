use super::{
    NativeSpanBatch, TraceReceiveFailure, bounds, decoded, fanout, increment_rejection,
    map_store_failure, request, transport,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use positron_domain::value::{ValueLimitProfile, ValueLimitProfileCandidate};
use prost::Message;

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
        let effective_profile = self.value_limit_profile;
        let system_profile =
            ValueLimitProfileCandidate::new(effective_profile.system_limits(), None)
                .validate()
                .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let decoded = match payload {
            request::OtlpPayload::Decoded { message, evidence } => {
                let limits = effective_profile.effective_limits().request();
                let compressed = usize::try_from(limits.compressed_bytes().value())
                    .map_err(|_| TraceReceiveFailure::TransportLimitExceeded)?;
                let decompressed = usize::try_from(limits.decompressed_bytes().value())
                    .map_err(|_| TraceReceiveFailure::TransportLimitExceeded)?;
                if evidence.wire_body_bytes() > compressed
                    || evidence.decompressed_message_bytes() > decompressed
                {
                    return Err(TraceReceiveFailure::TransportLimitExceeded);
                }
                *message
            },
            encoded => match transport::bounded_payload(encoded, effective_profile)? {
                transport::BoundedOtlpPayload::Protobuf(protobuf) => {
                    bounds::validate_protobuf(&protobuf, system_profile)?;
                    ExportTraceServiceRequest::decode(protobuf.as_slice())
                        .map_err(|_| TraceReceiveFailure::MalformedPayload)?
                },
                transport::BoundedOtlpPayload::Json(json) => {
                    bounds::validate_json(&json, system_profile)?;
                    serde_json::from_slice(&json)
                        .map_err(|_| TraceReceiveFailure::MalformedPayload)?
                },
            },
        };
        fanout::reserve_before_materialization(
            &decoded.resource_spans,
            system_profile,
            policy,
            capacity.as_mut(),
        )?;
        let (drafts, mut rejections) = decoded::native_records(decoded, &system_profile)?;
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
        let maximum_records = usize::try_from(
            self.value_limit_profile
                .effective_limits()
                .request()
                .records()
                .value(),
        )
        .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?;
        let maximum_decompressed = u64::from(
            self.value_limit_profile
                .effective_limits()
                .request()
                .decompressed_bytes()
                .value(),
        );
        let mut aggregate_attributes = 0_usize;
        let mut decoded_bytes = 0_u64;
        for draft in drafts {
            match draft.evaluate(policy, receiver, &self.value_limit_profile) {
                Ok(Some(record)) => {
                    if records.len() >= maximum_records {
                        increment_rejection(
                            &mut rejections,
                            crate::IngestFailureCode::ValueLimitExceeded,
                        );
                        continue;
                    }
                    if let Err(failure) =
                        positron_signals::TraceStore::canonical_encoded_record_bytes(
                            &self.value_limit_profile,
                            &record,
                        )
                    {
                        match map_store_failure(failure) {
                            TraceReceiveFailure::CapacityUnavailable => {
                                return Err(TraceReceiveFailure::CapacityUnavailable);
                            },
                            TraceReceiveFailure::ValueLimitExceeded => {
                                increment_rejection(
                                    &mut rejections,
                                    crate::IngestFailureCode::ValueLimitExceeded,
                                );
                                continue;
                            },
                            _ => {
                                increment_rejection(
                                    &mut rejections,
                                    crate::IngestFailureCode::InvalidRecord,
                                );
                                continue;
                            },
                        }
                    }
                    let record_decoded_bytes = match record.decoded_size_bytes() {
                        Ok(bytes) => u64::try_from(bytes)
                            .map_err(|_| TraceReceiveFailure::ValueLimitExceeded)?,
                        Err(failure) => match map_store_failure(failure) {
                            TraceReceiveFailure::CapacityUnavailable => {
                                return Err(TraceReceiveFailure::CapacityUnavailable);
                            },
                            TraceReceiveFailure::PolicyEvaluationFailed => {
                                return Err(TraceReceiveFailure::PolicyEvaluationFailed);
                            },
                            TraceReceiveFailure::ValueLimitExceeded => {
                                increment_rejection(
                                    &mut rejections,
                                    crate::IngestFailureCode::ValueLimitExceeded,
                                );
                                continue;
                            },
                            _ => {
                                increment_rejection(
                                    &mut rejections,
                                    crate::IngestFailureCode::InvalidRecord,
                                );
                                continue;
                            },
                        },
                    };
                    let record_attributes = record_attribute_count(&record)?;
                    if let Some(total) = aggregate_attributes
                        .checked_add(record_attributes)
                        .filter(|count| *count <= maximum_attributes)
                    {
                        if let Some(total_decoded) = decoded_bytes
                            .checked_add(record_decoded_bytes)
                            .filter(|bytes| *bytes <= maximum_decompressed)
                        {
                            aggregate_attributes = total;
                            decoded_bytes = total_decoded;
                            records.push(record);
                        } else {
                            increment_rejection(
                                &mut rejections,
                                crate::IngestFailureCode::ValueLimitExceeded,
                            );
                        }
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

fn record_attribute_count(
    record: &positron_signals::SpanObservation,
) -> Result<usize, TraceReceiveFailure> {
    let record_attributes = record
        .attributes()
        .iter()
        .try_fold(0_usize, |total, attribute| {
            total
                .checked_add(attribute.len())
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)
        })?;
    let event_attributes = record
        .details()
        .events()
        .iter()
        .try_fold(0_usize, |total, event| {
            let event_count = event
                .attributes()
                .iter()
                .try_fold(0_usize, |total, attribute| {
                    total
                        .checked_add(attribute.len())
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
                })?;
            total
                .checked_add(event_count)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)
        })?;
    let link_attributes = record
        .details()
        .links()
        .iter()
        .try_fold(0_usize, |total, link| {
            let link_count = link
                .attributes()
                .iter()
                .try_fold(0_usize, |total, attribute| {
                    total
                        .checked_add(attribute.len())
                        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
                })?;
            total
                .checked_add(link_count)
                .ok_or(TraceReceiveFailure::ValueLimitExceeded)
        })?;
    record_attributes
        .checked_add(event_attributes)
        .and_then(|total| total.checked_add(link_attributes))
        .ok_or(TraceReceiveFailure::ValueLimitExceeded)
}
