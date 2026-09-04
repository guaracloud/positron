use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use positron_domain::identity::TenantAttribution;
use positron_governance::AuthorizedContext;
use positron_kernel::{ResourceGovernor, ResourceReservation};

use super::{TraceReceiveFailure, ingest_attribution, reserve_trace_receiver_transport};

pub(super) enum OtlpPayload {
    Protobuf(Vec<u8>),
    GzipProtobuf(Vec<u8>),
    Json(Vec<u8>),
    GzipJson(Vec<u8>),
    Decoded {
        message: Box<ExportTraceServiceRequest>,
        evidence: OtlpGrpcTransportEvidence,
    },
}

/// Measurements captured after authenticated gRPC transport admission and
/// before the decoded request reaches the receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OtlpGrpcTransportEvidence {
    wire_body_bytes: usize,
    decompressed_message_bytes: usize,
}

impl OtlpGrpcTransportEvidence {
    /// Records the actual gRPC body and decompressed message sizes measured by
    /// the transport adapter. The body count includes each five-byte gRPC
    /// frame header, matching the compressed request limit's wire semantics.
    #[must_use]
    pub const fn prevalidated(wire_body_bytes: usize, decompressed_message_bytes: usize) -> Self {
        Self {
            wire_body_bytes,
            decompressed_message_bytes,
        }
    }

    pub(crate) const fn wire_body_bytes(self) -> usize {
        self.wire_body_bytes
    }

    pub(crate) const fn decompressed_message_bytes(self) -> usize {
        self.decompressed_message_bytes
    }
}

/// Supported OTLP Trace body encodings after HTTP metadata validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtlpTracesRequestEncoding {
    Protobuf,
    GzipProtobuf,
    Json,
    GzipJson,
}

/// OTLP bytes that can exist only after authoritative Tenant Attribution.
pub struct AuthenticatedOtlpTracesRequest<'authority> {
    pub(super) attribution: TenantAttribution,
    pub(super) payload: OtlpPayload,
    pub(super) capacity: Option<ResourceReservation<'authority>>,
    pub(super) receiver: crate::PolicyReceiver,
}

impl<'authority> AuthenticatedOtlpTracesRequest<'authority> {
    pub fn otlp_grpc_protobuf(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        protobuf: Vec<u8>,
    ) -> Result<Self, TraceReceiveFailure> {
        Self::admit(
            context,
            governor,
            OtlpPayload::Protobuf(protobuf),
            crate::PolicyReceiver::OtlpGrpc,
        )
    }

    pub fn otlp_grpc_gzip_protobuf(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        protobuf: Vec<u8>,
    ) -> Result<Self, TraceReceiveFailure> {
        Self::admit(
            context,
            governor,
            OtlpPayload::GzipProtobuf(protobuf),
            crate::PolicyReceiver::OtlpGrpc,
        )
    }

    pub fn otlp_http(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        encoding: OtlpTracesRequestEncoding,
        body: Vec<u8>,
    ) -> Result<Self, TraceReceiveFailure> {
        Self::admit(
            context,
            governor,
            payload(encoding, body),
            receiver(encoding),
        )
    }

    /// Accepts a decoded message from the authenticated bounded gRPC transport.
    pub fn decoded_otlp_grpc_after_transport_admission(
        context: AuthorizedContext,
        decoded: ExportTraceServiceRequest,
        evidence: OtlpGrpcTransportEvidence,
        capacity: ResourceReservation<'authority>,
    ) -> Result<Self, TraceReceiveFailure> {
        Ok(Self {
            attribution: ingest_attribution(context)?,
            payload: OtlpPayload::Decoded {
                message: Box::new(decoded),
                evidence,
            },
            capacity: Some(capacity),
            receiver: crate::PolicyReceiver::OtlpGrpc,
        })
    }

    /// Accepts encoded bytes only after authentication and transport admission.
    pub fn encoded_otlp_http_after_transport_admission(
        context: AuthorizedContext,
        encoding: OtlpTracesRequestEncoding,
        body: Vec<u8>,
        capacity: ResourceReservation<'authority>,
    ) -> Result<Self, TraceReceiveFailure> {
        Ok(Self {
            attribution: ingest_attribution(context)?,
            payload: payload(encoding, body),
            capacity: Some(capacity),
            receiver: receiver(encoding),
        })
    }

    fn admit(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        payload: OtlpPayload,
        receiver: crate::PolicyReceiver,
    ) -> Result<Self, TraceReceiveFailure> {
        let attribution = ingest_attribution(context)?;
        let maximum_request_bytes = usize::try_from(
            positron_domain::value::ValueLimitProfile::release_1_system_maximum()
                .system_limits()
                .request()
                .compressed_bytes()
                .value(),
        )
        .map_err(|_| TraceReceiveFailure::TransportLimitExceeded)?;
        if payload.encoded_len() > maximum_request_bytes {
            return Err(TraceReceiveFailure::TransportLimitExceeded);
        }
        let capacity = reserve_trace_receiver_transport(context, governor)?;
        Ok(Self {
            attribution,
            payload,
            capacity: Some(capacity),
            receiver,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_only_protobuf(attribution: TenantAttribution, protobuf: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::Protobuf(protobuf))
    }

    #[cfg(test)]
    pub(crate) fn test_only_json(attribution: TenantAttribution, json: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::Json(json))
    }

    #[cfg(test)]
    pub(crate) fn test_only_gzip_protobuf(
        attribution: TenantAttribution,
        protobuf: Vec<u8>,
    ) -> Self {
        Self::test_only(attribution, OtlpPayload::GzipProtobuf(protobuf))
    }

    #[cfg(test)]
    pub(crate) fn test_only_gzip_json(attribution: TenantAttribution, json: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::GzipJson(json))
    }

    #[cfg(test)]
    fn test_only(attribution: TenantAttribution, payload: OtlpPayload) -> Self {
        Self {
            attribution,
            payload,
            capacity: None,
            receiver: crate::PolicyReceiver::OtlpGrpc,
        }
    }
}

fn payload(encoding: OtlpTracesRequestEncoding, body: Vec<u8>) -> OtlpPayload {
    match encoding {
        OtlpTracesRequestEncoding::Protobuf => OtlpPayload::Protobuf(body),
        OtlpTracesRequestEncoding::GzipProtobuf => OtlpPayload::GzipProtobuf(body),
        OtlpTracesRequestEncoding::Json => OtlpPayload::Json(body),
        OtlpTracesRequestEncoding::GzipJson => OtlpPayload::GzipJson(body),
    }
}

const fn receiver(encoding: OtlpTracesRequestEncoding) -> crate::PolicyReceiver {
    match encoding {
        OtlpTracesRequestEncoding::Protobuf | OtlpTracesRequestEncoding::GzipProtobuf => {
            crate::PolicyReceiver::OtlpHttpProtobuf
        },
        OtlpTracesRequestEncoding::Json | OtlpTracesRequestEncoding::GzipJson => {
            crate::PolicyReceiver::OtlpHttpJson
        },
    }
}

impl OtlpPayload {
    fn encoded_len(&self) -> usize {
        match self {
            Self::Protobuf(bytes)
            | Self::GzipProtobuf(bytes)
            | Self::Json(bytes)
            | Self::GzipJson(bytes) => bytes.len(),
            Self::Decoded { message, .. } => prost::Message::encoded_len(message.as_ref()),
        }
    }
}
