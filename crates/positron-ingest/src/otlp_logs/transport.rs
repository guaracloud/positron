use std::io::Read;

use flate2::read::MultiGzDecoder;

use super::{MAX_REQUEST_BYTES, OtlpPayload, ReceiveFailure};

pub(super) fn bounded_protobuf(payload: OtlpPayload) -> Result<Vec<u8>, ReceiveFailure> {
    match payload {
        OtlpPayload::Protobuf(bytes) => {
            if bytes.len() > MAX_REQUEST_BYTES {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(bytes)
        },
        OtlpPayload::GzipProtobuf(bytes) => {
            if bytes.len() > MAX_REQUEST_BYTES {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            let mut decoded =
                Vec::with_capacity(bytes.len().saturating_mul(4).min(MAX_REQUEST_BYTES));
            MultiGzDecoder::new(bytes.as_slice())
                .take((MAX_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut decoded)
                .map_err(|_| ReceiveFailure::MalformedCompression)?;
            if decoded.len() > MAX_REQUEST_BYTES {
                return Err(ReceiveFailure::TransportLimitExceeded);
            }
            Ok(decoded)
        },
    }
}
