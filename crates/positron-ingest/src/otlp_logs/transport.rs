use std::io::Read;

use flate2::read::MultiGzDecoder;

use positron_domain::value::ValueLimitProfile;

use super::{OtlpPayload, ReceiveFailure};

pub(super) fn bounded_protobuf(
    payload: OtlpPayload,
    profile: ValueLimitProfile,
) -> Result<Vec<u8>, ReceiveFailure> {
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
            Ok(bytes)
        },
        OtlpPayload::GzipProtobuf(bytes) => {
            if bytes.len() > compressed {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            let mut decoded = Vec::with_capacity(bytes.len().saturating_mul(4).min(decompressed));
            let read_limit = u64::try_from(decompressed)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(ReceiveFailure::TransportLimitExceeded)?;
            MultiGzDecoder::new(bytes.as_slice())
                .take(read_limit)
                .read_to_end(&mut decoded)
                .map_err(|_| ReceiveFailure::MalformedCompression)?;
            if decoded.len() > decompressed {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(decoded)
        },
        OtlpPayload::Decoded(_) => Err(ReceiveFailure::MalformedPayload),
    }
}
