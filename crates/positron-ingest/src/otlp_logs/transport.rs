use std::io::Read;

use flate2::read::MultiGzDecoder;

use positron_domain::value::ValueLimitProfile;

use super::{OtlpPayload, ReceiveFailure};

pub(super) enum BoundedOtlpPayload {
    Protobuf(Vec<u8>),
    Json(Vec<u8>),
}

pub(super) fn bounded_payload(
    payload: OtlpPayload,
    profile: ValueLimitProfile,
) -> Result<BoundedOtlpPayload, ReceiveFailure> {
    let request = profile.effective_limits().request();
    let compressed = usize::try_from(request.compressed_bytes().value())
        .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
    let decompressed = usize::try_from(request.decompressed_bytes().value())
        .map_err(|_| ReceiveFailure::TransportLimitExceeded)?;
    match payload {
        OtlpPayload::Protobuf(bytes) => {
            if bytes.len() > compressed || bytes.len() > decompressed {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Protobuf(bytes))
        },
        OtlpPayload::GzipProtobuf(bytes) => {
            if bytes.len() > compressed {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Protobuf(decompress(
                bytes,
                decompressed,
            )?))
        },
        OtlpPayload::Json(bytes) => {
            if bytes.len() > compressed || bytes.len() > decompressed {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Json(bytes))
        },
        OtlpPayload::GzipJson(bytes) => {
            if bytes.len() > compressed {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(BoundedOtlpPayload::Json(decompress(bytes, decompressed)?))
        },
        OtlpPayload::Decoded(_) => Err(ReceiveFailure::MalformedPayload),
    }
}

fn decompress(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>, ReceiveFailure> {
    let mut decoded = Vec::with_capacity(bytes.len().saturating_mul(4).min(maximum));
    let read_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(ReceiveFailure::TransportLimitExceeded)?;
    MultiGzDecoder::new(bytes.as_slice())
        .take(read_limit)
        .read_to_end(&mut decoded)
        .map_err(|_| ReceiveFailure::MalformedCompression)?;
    if decoded.len() > maximum {
        return Err(ReceiveFailure::TransportLimitExceeded);
    }
    Ok(decoded)
}
