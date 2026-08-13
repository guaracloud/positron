use crate::data_protection::DataProtection;

use super::super::types::{CatalogFailure, CatalogFailureCode, CatalogGenerationId, CatalogSecret};

const MARKER_MAGIC: [u8; 8] = *b"PMARK01\0";
const MARKER_VERSION: u16 = 1;
pub(crate) const MARKER_BYTES: usize = 82;
const MARKER_MAC_DOMAIN: &[u8] = b"positron-catalog-marker-v1";

pub(super) fn encode_marker(
    secret: &CatalogSecret,
    number: u64,
    generation: CatalogGenerationId,
) -> Result<[u8; MARKER_BYTES], CatalogFailure> {
    let mut marker = Vec::with_capacity(MARKER_BYTES);
    marker.extend_from_slice(&MARKER_MAGIC);
    marker.extend_from_slice(&MARKER_VERSION.to_be_bytes());
    marker.extend_from_slice(&number.to_be_bytes());
    marker.extend_from_slice(&generation.0);
    let mac = hmac(secret, &marker)?;
    marker.extend_from_slice(&mac);
    marker
        .try_into()
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))
}

pub(super) fn decode_marker(
    secret: &CatalogSecret,
    encoded: &[u8],
) -> Result<MarkerDecode, CatalogFailure> {
    let Some((magic, remaining)) = encoded.split_first_chunk::<8>() else {
        return Ok(MarkerDecode::Torn);
    };
    let Some((version, remaining)) = remaining.split_first_chunk::<2>() else {
        return Ok(MarkerDecode::Torn);
    };
    let Some((number_bytes, remaining)) = remaining.split_first_chunk::<8>() else {
        return Ok(MarkerDecode::Torn);
    };
    let Some((generation_bytes, remaining)) = remaining.split_first_chunk::<32>() else {
        return Ok(MarkerDecode::Torn);
    };
    let Some((stored_mac, trailing)) = remaining.split_first_chunk::<32>() else {
        return Ok(MarkerDecode::Torn);
    };
    if !trailing.is_empty() || *magic != MARKER_MAGIC {
        return Ok(MarkerDecode::Corrupt);
    }
    if *version != MARKER_VERSION.to_be_bytes() {
        return Ok(MarkerDecode::Unsupported);
    }
    let number = u64::from_be_bytes(*number_bytes);
    let generation = CatalogGenerationId(*generation_bytes);
    let authenticated = encoded
        .get(..50)
        .ok_or_else(|| CatalogFailure::new(CatalogFailureCode::IntegrityCorruption))?;
    let mut domain_payload = Vec::with_capacity(MARKER_MAC_DOMAIN.len() + authenticated.len());
    domain_payload.extend_from_slice(MARKER_MAC_DOMAIN);
    domain_payload.extend_from_slice(authenticated);
    if DataProtection::verify_authentication(&secret.marker_key, &domain_payload, stored_mac)
        .is_err()
    {
        return Ok(MarkerDecode::AuthenticationFailed);
    }
    if number == 0 || generation == CatalogGenerationId::ORIGIN {
        return Ok(MarkerDecode::Corrupt);
    }
    Ok(MarkerDecode::Published(number, generation))
}

fn hmac(secret: &CatalogSecret, payload: &[u8]) -> Result<[u8; 32], CatalogFailure> {
    let mut authenticated = Vec::with_capacity(MARKER_MAC_DOMAIN.len() + payload.len());
    authenticated.extend_from_slice(MARKER_MAC_DOMAIN);
    authenticated.extend_from_slice(payload);
    DataProtection::authenticate(&secret.marker_key, &authenticated)
        .map_err(|_| CatalogFailure::new(CatalogFailureCode::AuthenticationFailed))
}
pub(super) enum MarkerDecode {
    Published(u64, CatalogGenerationId),
    Torn,
    AuthenticationFailed,
    Corrupt,
    Unsupported,
}
