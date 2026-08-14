use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use positron_governance::AuthorizedContext;
use positron_kernel::{ResourceGovernor, ResourceReservation};
use prost::Message;

use super::{ReceiveFailure, ingest_attribution, reserve_otlp_logs_transport};

pub(super) enum OtlpPayload {
    Protobuf(Vec<u8>),
    GzipProtobuf(Vec<u8>),
    Json(Vec<u8>),
    GzipJson(Vec<u8>),
    Decoded(Box<ExportLogsServiceRequest>),
}

/// Supported OTLP Logs request body encodings after HTTP metadata validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OtlpLogsRequestEncoding {
    Protobuf,
    GzipProtobuf,
    Json,
    GzipJson,
}

/// OTLP bytes that can exist only after authoritative tenant attribution.
///
/// ```compile_fail
/// use positron_ingest::AuthenticatedOtlpLogsRequest;
///
/// // Raw protocol bytes cannot reach the Receiver Adapter without a checked
/// // Tenant Attribution created by the identity boundary.
/// let _ = AuthenticatedOtlpLogsRequest::new(vec![0_u8]);
/// ```
pub struct AuthenticatedOtlpLogsRequest<'authority> {
    pub(super) attribution: TenantAttribution,
    pub(super) payload: OtlpPayload,
    pub(super) capacity: Option<ResourceReservation<'authority>>,
    pub(super) receiver: crate::PolicyReceiver,
}

impl<'authority> AuthenticatedOtlpLogsRequest<'authority> {
    pub fn otlp_grpc_protobuf(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        protobuf: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
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
        gzip_protobuf: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        Self::admit(
            context,
            governor,
            OtlpPayload::GzipProtobuf(gzip_protobuf),
            crate::PolicyReceiver::OtlpGrpc,
        )
    }

    pub fn otlp_http(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        encoding: OtlpLogsRequestEncoding,
        body: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        Self::admit(
            context,
            governor,
            payload(encoding, body),
            http_receiver(encoding),
        )
    }

    pub fn loki_otlp(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        encoding: OtlpLogsRequestEncoding,
        body: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        Self::admit(
            context,
            governor,
            payload(encoding, body),
            loki_otlp_receiver(encoding),
        )
    }

    /// Accepts a message decoded by an authenticated bounded gRPC transport.
    pub fn decoded_otlp_grpc_after_transport_admission(
        context: AuthorizedContext,
        decoded: ExportLogsServiceRequest,
        capacity: ResourceReservation<'authority>,
    ) -> Result<Self, ReceiveFailure> {
        Ok(Self {
            attribution: ingest_attribution(context)?,
            payload: OtlpPayload::Decoded(Box::new(decoded)),
            capacity: Some(capacity),
            receiver: crate::PolicyReceiver::OtlpGrpc,
        })
    }

    /// Accepts encoded bytes only after authentication and transport admission.
    pub fn encoded_otlp_http_after_transport_admission(
        context: AuthorizedContext,
        encoding: OtlpLogsRequestEncoding,
        body: Vec<u8>,
        capacity: ResourceReservation<'authority>,
    ) -> Result<Self, ReceiveFailure> {
        Ok(Self {
            attribution: ingest_attribution(context)?,
            payload: payload(encoding, body),
            capacity: Some(capacity),
            receiver: http_receiver(encoding),
        })
    }

    pub fn encoded_loki_otlp_after_transport_admission(
        context: AuthorizedContext,
        encoding: OtlpLogsRequestEncoding,
        body: Vec<u8>,
        capacity: ResourceReservation<'authority>,
    ) -> Result<Self, ReceiveFailure> {
        Ok(Self {
            attribution: ingest_attribution(context)?,
            payload: payload(encoding, body),
            capacity: Some(capacity),
            receiver: loki_otlp_receiver(encoding),
        })
    }

    fn admit(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        payload: OtlpPayload,
        receiver: crate::PolicyReceiver,
    ) -> Result<Self, ReceiveFailure> {
        let attribution = ingest_attribution(context)?;
        let maximum_request_bytes = usize::try_from(
            ValueLimitProfile::release_1_system_maximum()
                .system_limits()
                .request()
                .compressed_bytes()
                .value(),
        )
        .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
        if payload.encoded_len() > maximum_request_bytes {
            return Err(ReceiveFailure::TransportLimitExceeded);
        }
        let capacity = reserve_otlp_logs_transport(context, governor)?;
        Ok(Self {
            attribution,
            payload,
            capacity: Some(capacity),
            receiver,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_only_protobuf(attribution: TenantAttribution, protobuf: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::Protobuf(protobuf))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_only_gzip(attribution: TenantAttribution, gzip_protobuf: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::GzipProtobuf(gzip_protobuf))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_only_json(attribution: TenantAttribution, json: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::Json(json))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_only_gzip_json(attribution: TenantAttribution, gzip_json: Vec<u8>) -> Self {
        Self::test_only(attribution, OtlpPayload::GzipJson(gzip_json))
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

fn payload(encoding: OtlpLogsRequestEncoding, body: Vec<u8>) -> OtlpPayload {
    match encoding {
        OtlpLogsRequestEncoding::Protobuf => OtlpPayload::Protobuf(body),
        OtlpLogsRequestEncoding::GzipProtobuf => OtlpPayload::GzipProtobuf(body),
        OtlpLogsRequestEncoding::Json => OtlpPayload::Json(body),
        OtlpLogsRequestEncoding::GzipJson => OtlpPayload::GzipJson(body),
    }
}

const fn http_receiver(encoding: OtlpLogsRequestEncoding) -> crate::PolicyReceiver {
    match encoding {
        OtlpLogsRequestEncoding::Protobuf | OtlpLogsRequestEncoding::GzipProtobuf => {
            crate::PolicyReceiver::OtlpHttpProtobuf
        },
        OtlpLogsRequestEncoding::Json | OtlpLogsRequestEncoding::GzipJson => {
            crate::PolicyReceiver::OtlpHttpJson
        },
    }
}

const fn loki_otlp_receiver(encoding: OtlpLogsRequestEncoding) -> crate::PolicyReceiver {
    match encoding {
        OtlpLogsRequestEncoding::Protobuf | OtlpLogsRequestEncoding::GzipProtobuf => {
            crate::PolicyReceiver::LokiOtlpProtobuf
        },
        OtlpLogsRequestEncoding::Json | OtlpLogsRequestEncoding::GzipJson => {
            crate::PolicyReceiver::LokiOtlpJson
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
            Self::Decoded(message) => message.encoded_len(),
        }
    }
}
