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
    let read_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(TraceReceiveFailure::TransportLimitExceeded)?;
    let initial_capacity = bytes
        .len()
        .checked_mul(4)
        .ok_or(TraceReceiveFailure::TransportLimitExceeded)?
        .min(maximum);
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(initial_capacity)
        .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
    let mut decoder = MultiGzDecoder::new(bytes.as_slice()).take(read_limit);
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|_| TraceReceiveFailure::MalformedCompression)?;
        if read == 0 {
            break;
        }
        let new_length = decoded
            .len()
            .checked_add(read)
            .ok_or(TraceReceiveFailure::TransportLimitExceeded)?;
        if new_length > maximum {
            return Err(TraceReceiveFailure::TransportLimitExceeded);
        }
        decoded
            .try_reserve(read)
            .map_err(|_| TraceReceiveFailure::CapacityUnavailable)?;
        decoded.extend_from_slice(&chunk[..read]);
    }
    Ok(decoded)
}
