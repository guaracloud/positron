use std::io::Read;

use flate2::read::MultiGzDecoder;
use positron_domain::value::ValueLimitProfile;

use super::{TraceReceiveFailure, request::OtlpPayload};

pub(super) enum BoundedOtlpPayload {
    Protobuf(Vec<u8>),
    Json(Vec<u8>),
}

pub(super) fn bounded_payload(
    payload: OtlpPayload,
    profile: ValueLimitProfile,
) -> Result<BoundedOtlpPayload, TraceReceiveFailure> {
    let request = profile.effective_limits().request();
    let compressed = usize::try_from(request.compressed_bytes().value())
        .map_err(|_| TraceReceiveFailure::TransportLimitExceeded)?;
    let decompressed = usize::try_from(request.decompressed_bytes().value())
        .map_err(|_| TraceReceiveFailure::TransportLimitExceeded)?;
    match payload {
        OtlpPayload::Protobuf(bytes) => {
            if bytes.len() > compressed || bytes.len() > decompressed {
                return Err(TraceReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Protobuf(bytes))
        },
        OtlpPayload::GzipProtobuf(bytes) => {
            if bytes.len() > compressed {
                return Err(TraceReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Protobuf(decompress(
                bytes,
                decompressed,
            )?))
        },
        OtlpPayload::Json(bytes) => {
            if bytes.len() > compressed || bytes.len() > decompressed {
                return Err(TraceReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Json(bytes))
        },
        OtlpPayload::GzipJson(bytes) => {
            if bytes.len() > compressed {
                return Err(TraceReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Json(decompress(bytes, decompressed)?))
        },
        OtlpPayload::Decoded { .. } => Err(TraceReceiveFailure::MalformedPayload),
    }
}

fn decompress(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>, TraceReceiveFailure> {
    let mut decoded = Vec::with_capacity(bytes.len().saturating_mul(4).min(maximum));
    let read_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(TraceReceiveFailure::TransportLimitExceeded)?;
    MultiGzDecoder::new(bytes.as_slice())
        .take(read_limit)
        .read_to_end(&mut decoded)
        .map_err(|_| TraceReceiveFailure::MalformedCompression)?;
    if decoded.len() > maximum {
        return Err(TraceReceiveFailure::TransportLimitExceeded);
    }
    Ok(decoded)
}
