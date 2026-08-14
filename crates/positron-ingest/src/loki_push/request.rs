use positron_domain::identity::TenantAttribution;
use positron_domain::value::ValueLimitProfile;
use positron_governance::AuthorizedContext;
use positron_kernel::{ResourceGovernor, ResourceReservation};

use crate::{ReceiveFailure, reserve_log_receiver_transport};

use super::super::otlp_logs::ingest_attribution;

/// Supported Loki Push request body encodings after HTTP metadata validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LokiPushRequestEncoding {
    Json,
    GzipJson,
    DeflateJson,
    SnappyProtobuf,
}

pub(super) enum LokiPushPayload {
    Json(Vec<u8>),
    GzipJson(Vec<u8>),
    DeflateJson(Vec<u8>),
    SnappyProtobuf(Vec<u8>),
}

pub(super) enum BoundedLokiPayload {
    Json(Vec<u8>),
    Protobuf(Vec<u8>),
}

/// Loki Push bytes that can exist only after authoritative tenant attribution.
pub struct AuthenticatedLokiPushRequest<'authority> {
    pub(super) attribution: TenantAttribution,
    pub(super) payload: LokiPushPayload,
    pub(super) capacity: Option<ResourceReservation<'authority>>,
}

impl<'authority> AuthenticatedLokiPushRequest<'authority> {
    pub fn json(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        json: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        let attribution = ingest_attribution(context)?;
        ensure_encoded_limit(json.len(), ValueLimitProfile::release_1_system_maximum())?;
        let capacity = reserve_log_receiver_transport(context, governor)?;
        Ok(Self {
            attribution,
            payload: LokiPushPayload::Json(json),
            capacity: Some(capacity),
        })
    }

    pub fn snappy_protobuf(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        snappy_protobuf: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        let attribution = ingest_attribution(context)?;
        ensure_compressed_limit(
            snappy_protobuf.len(),
            ValueLimitProfile::release_1_system_maximum(),
        )?;
        let capacity = reserve_log_receiver_transport(context, governor)?;
        Ok(Self {
            attribution,
            payload: LokiPushPayload::SnappyProtobuf(snappy_protobuf),
            capacity: Some(capacity),
        })
    }

    pub fn gzip_json(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        gzip_json: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        let attribution = ingest_attribution(context)?;
        ensure_compressed_limit(
            gzip_json.len(),
            ValueLimitProfile::release_1_system_maximum(),
        )?;
        let capacity = reserve_log_receiver_transport(context, governor)?;
        Ok(Self {
            attribution,
            payload: LokiPushPayload::GzipJson(gzip_json),
            capacity: Some(capacity),
        })
    }

    pub fn deflate_json(
        context: AuthorizedContext,
        governor: ResourceGovernor<'authority>,
        deflate_json: Vec<u8>,
    ) -> Result<Self, ReceiveFailure> {
        let attribution = ingest_attribution(context)?;
        ensure_compressed_limit(
            deflate_json.len(),
            ValueLimitProfile::release_1_system_maximum(),
        )?;
        let capacity = reserve_log_receiver_transport(context, governor)?;
        Ok(Self {
            attribution,
            payload: LokiPushPayload::DeflateJson(deflate_json),
            capacity: Some(capacity),
        })
    }

    /// Accepts encoded bytes only after authentication and transport admission.
    pub fn encoded_after_transport_admission(
        context: AuthorizedContext,
        encoding: LokiPushRequestEncoding,
        body: Vec<u8>,
        capacity: ResourceReservation<'authority>,
    ) -> Result<Self, ReceiveFailure> {
        let payload = match encoding {
            LokiPushRequestEncoding::Json => LokiPushPayload::Json(body),
            LokiPushRequestEncoding::GzipJson => LokiPushPayload::GzipJson(body),
            LokiPushRequestEncoding::DeflateJson => LokiPushPayload::DeflateJson(body),
            LokiPushRequestEncoding::SnappyProtobuf => LokiPushPayload::SnappyProtobuf(body),
        };
        Ok(Self {
            attribution: ingest_attribution(context)?,
            payload,
            capacity: Some(capacity),
        })
    }
}

impl LokiPushPayload {
    pub(super) fn bounded(
        self,
        profile: ValueLimitProfile,
    ) -> Result<BoundedLokiPayload, ReceiveFailure> {
        match self {
            Self::Json(json) => {
                ensure_encoded_limit(json.len(), profile)?;
                Ok(BoundedLokiPayload::Json(json))
            },
            Self::GzipJson(gzip) => {
                let maximum = decompression_limits(gzip.len(), profile)?;
                bounded_read(MultiGzDecoder::new(gzip.as_slice()), maximum)
                    .map(BoundedLokiPayload::Json)
            },
            Self::DeflateJson(deflate) => {
                let maximum = decompression_limits(deflate.len(), profile)?;
                bounded_read(DeflateDecoder::new(deflate.as_slice()), maximum)
                    .map(BoundedLokiPayload::Json)
            },
            Self::SnappyProtobuf(snappy) => {
                ensure_compressed_limit(snappy.len(), profile)?;
                let maximum = usize::try_from(
                    profile
                        .effective_limits()
                        .request()
                        .decompressed_bytes()
                        .value(),
                )
                .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
                let length = snap::raw::decompress_len(&snappy)
                    .map_err(|_| ReceiveFailure::MalformedCompression)?;
                if length > maximum {
                    return Err(ReceiveFailure::TransportLimitExceeded);
                }
                let mut protobuf = vec![0_u8; length];
                let written = snap::raw::Decoder::new()
                    .decompress(&snappy, &mut protobuf)
                    .map_err(|_| ReceiveFailure::MalformedCompression)?;
                if written != length {
                    return Err(ReceiveFailure::MalformedCompression);
                }
                Ok(BoundedLokiPayload::Protobuf(protobuf))
            },
        }
    }
}

fn decompression_limits(
    compressed_bytes: usize,
    profile: ValueLimitProfile,
) -> Result<usize, ReceiveFailure> {
    ensure_compressed_limit(compressed_bytes, profile)?;
    usize::try_from(
        profile
            .effective_limits()
            .request()
            .decompressed_bytes()
            .value(),
    )
    .map_err(|_| ReceiveFailure::TransportLimitExceeded)
}

fn bounded_read(reader: impl Read, maximum: usize) -> Result<Vec<u8>, ReceiveFailure> {
    let read_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(ReceiveFailure::TransportLimitExceeded)?;
    let mut decoded = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut decoded)
        .map_err(|_| ReceiveFailure::MalformedCompression)?;
    if decoded.len() > maximum {
        return Err(ReceiveFailure::TransportLimitExceeded);
    }
    Ok(decoded)
}

fn ensure_compressed_limit(bytes: usize, profile: ValueLimitProfile) -> Result<(), ReceiveFailure> {
    let maximum = usize::try_from(
        profile
            .effective_limits()
            .request()
            .compressed_bytes()
            .value(),
    )
    .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
    if bytes > maximum {
        return Err(ReceiveFailure::TransportLimitExceeded);
    }
    Ok(())
}

fn ensure_encoded_limit(bytes: usize, profile: ValueLimitProfile) -> Result<(), ReceiveFailure> {
    let limits = profile.effective_limits().request();
    let compressed = usize::try_from(limits.compressed_bytes().value())
        .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
    let decompressed = usize::try_from(limits.decompressed_bytes().value())
        .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
    if bytes > compressed || bytes > decompressed {
        return Err(ReceiveFailure::TransportLimitExceeded);
    }
    Ok(())
}
use std::io::Read;

use flate2::read::{DeflateDecoder, MultiGzDecoder};
