use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::{LedgerFailure, LedgerFailureCode, SegmentId, SegmentKeyRoute, SegmentScope};

const METADATA_MAGIC: &[u8; 8] = b"PSEGMET1";
const SEGMENT_MAGIC: &[u8; 8] = b"PSEGACT3";
const METADATA_VERSION: u16 = 1;
const SEGMENT_VERSION: u16 = 2;
pub(super) const METADATA_BYTES: usize = 8 + 2 + 1 + 16 + 1 + 4 + 16 + 8;
const FRAME_ALGORITHM_AES_256_GCM: u16 = 1;
const WRAPPING_ALGORITHM_AES_256_KWP: u16 = 1;
pub(super) const HEADER_PREFIX_BYTES: usize = 8 + 2 + 2 + 2 + 2 + 16 + 8 + 4;
const MAX_WRAPPED_KEY_BYTES: usize = 256;
const MAX_ENCRYPTED_METADATA_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SegmentState {
    Active,
    Sealed,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SegmentMetadata {
    pub(super) scope: SegmentScope,
    pub(super) id: SegmentId,
    pub(super) state: SegmentState,
    pub(super) base_position: CommitPosition,
}

pub(super) struct SegmentHeader<'a> {
    pub(super) route: SegmentKeyRoute,
    pub(super) wrapped_key: &'a [u8],
    pub(super) encrypted_metadata: &'a [u8],
    pub(super) encoded_bytes: usize,
}

pub(super) fn encode_metadata(metadata: SegmentMetadata) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(METADATA_BYTES);
    bytes.extend_from_slice(METADATA_MAGIC);
    bytes.extend_from_slice(&METADATA_VERSION.to_be_bytes());
    bytes.push(match metadata.state {
        SegmentState::Active => 1,
        SegmentState::Sealed => 2,
        SegmentState::Retired => 3,
    });
    bytes.extend_from_slice(&metadata.scope.tenant.to_bytes());
    bytes.push(match metadata.scope.signal {
        SignalKind::Logs => 1,
        SignalKind::Traces => 2,
    });
    bytes.extend_from_slice(&metadata.scope.shard.value().to_be_bytes());
    bytes.extend_from_slice(&metadata.id.to_bytes());
    bytes.extend_from_slice(&metadata.base_position.value().to_be_bytes());
    bytes
}

pub(super) fn decode_metadata(bytes: &[u8]) -> Result<Option<SegmentMetadata>, LedgerFailure> {
    if !bytes.starts_with(METADATA_MAGIC) {
        return Ok(None);
    }
    if bytes.len() != METADATA_BYTES
        || bytes.get(8..10) != Some(METADATA_VERSION.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let state = match bytes.get(10).copied() {
        Some(1) => SegmentState::Active,
        Some(2) => SegmentState::Sealed,
        Some(3) => SegmentState::Retired,
        _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    };
    let tenant: [u8; 16] = exact(bytes, 11, 16)?;
    let signal = match bytes.get(27).copied() {
        Some(1) => SignalKind::Logs,
        Some(2) => SignalKind::Traces,
        _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    };
    let shard = u32::from_be_bytes(exact(bytes, 28, 4)?);
    let id = SegmentId::new(exact(bytes, 32, 16)?)?;
    let base = u64::from_be_bytes(exact(bytes, 48, 8)?);
    Ok(Some(SegmentMetadata {
        scope: SegmentScope::new(
            TenantId::from_bytes(tenant)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
            signal,
            VirtualShardId::new(shard)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        ),
        id,
        state,
        base_position: position_from_value(base)?,
    }))
}

pub(super) fn encode_header(
    route: SegmentKeyRoute,
    wrapped_key: &[u8],
    encrypted_metadata: &[u8],
) -> Result<Vec<u8>, LedgerFailure> {
    if wrapped_key.is_empty()
        || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES
        || encrypted_metadata.is_empty()
        || encrypted_metadata.len() > MAX_ENCRYPTED_METADATA_BYTES
    {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let wrapped_length = u32::try_from(wrapped_key.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let metadata_length = u32::try_from(encrypted_metadata.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut bytes =
        Vec::with_capacity(HEADER_PREFIX_BYTES + wrapped_key.len() + 4 + encrypted_metadata.len());
    bytes.extend_from_slice(SEGMENT_MAGIC);
    bytes.extend_from_slice(&SEGMENT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&FRAME_ALGORITHM_AES_256_GCM.to_be_bytes());
    bytes.extend_from_slice(&WRAPPING_ALGORITHM_AES_256_KWP.to_be_bytes());
    bytes.extend_from_slice(&route.provider_family.to_be_bytes());
    bytes.extend_from_slice(&route.provider_reference);
    bytes.extend_from_slice(&route.provider_key_epoch.to_be_bytes());
    bytes.extend_from_slice(&wrapped_length.to_be_bytes());
    bytes.extend_from_slice(wrapped_key);
    bytes.extend_from_slice(&metadata_length.to_be_bytes());
    bytes.extend_from_slice(encrypted_metadata);
    Ok(bytes)
}

pub(super) fn decode_header(bytes: &[u8]) -> Result<SegmentHeader<'_>, LedgerFailure> {
    if bytes.get(..8) != Some(SEGMENT_MAGIC.as_slice())
        || bytes.get(8..10) != Some(SEGMENT_VERSION.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    if bytes.get(10..12) != Some(FRAME_ALGORITHM_AES_256_GCM.to_be_bytes().as_slice())
        || bytes.get(12..14) != Some(WRAPPING_ALGORITHM_AES_256_KWP.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let provider_family = u16::from_be_bytes(exact(bytes, 14, 2)?);
    let provider_reference = exact(bytes, 16, 16)?;
    let provider_key_epoch = u64::from_be_bytes(exact(bytes, 32, 8)?);
    if provider_family == 0
        || provider_reference.iter().all(|byte| *byte == 0)
        || provider_key_epoch == 0
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let wrapped_length = usize::try_from(u32::from_be_bytes(exact(bytes, 40, 4)?))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if wrapped_length == 0 || wrapped_length > MAX_WRAPPED_KEY_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let metadata_length_offset = HEADER_PREFIX_BYTES
        .checked_add(wrapped_length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let metadata_offset = metadata_length_offset
        .checked_add(4)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let metadata_length =
        usize::try_from(u32::from_be_bytes(exact(bytes, metadata_length_offset, 4)?))
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if metadata_length == 0 || metadata_length > MAX_ENCRYPTED_METADATA_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let encoded_bytes = metadata_offset
        .checked_add(metadata_length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let wrapped_key = bytes
        .get(HEADER_PREFIX_BYTES..metadata_length_offset)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let encrypted_metadata = bytes
        .get(metadata_offset..encoded_bytes)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    Ok(SegmentHeader {
        route: SegmentKeyRoute {
            provider_family,
            provider_reference,
            provider_key_epoch,
        },
        wrapped_key,
        encrypted_metadata,
        encoded_bytes,
    })
}

pub(super) fn position_from_value(value: u64) -> Result<CommitPosition, LedgerFailure> {
    if value == 0 {
        return Ok(CommitPosition::origin());
    }
    CommitPosition::origin()
        .advance_by(
            std::num::NonZeroU64::new(value)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
}

fn exact<const N: usize>(
    bytes: &[u8],
    start: usize,
    length: usize,
) -> Result<[u8; N], LedgerFailure> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    bytes
        .get(start..end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}
