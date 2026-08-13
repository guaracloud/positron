use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};

use super::{LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope};

const METADATA_MAGIC: &[u8; 8] = b"PSEGMET1";
const SEGMENT_MAGIC: &[u8; 8] = b"PSEGACT1";
const VERSION: u16 = 1;
pub(super) const METADATA_BYTES: usize = 8 + 2 + 1 + 16 + 1 + 4 + 16 + 8;
const HEADER_PREFIX_BYTES: usize = 8 + 2 + METADATA_BYTES + 4;
const MAX_WRAPPED_KEY_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SegmentState {
    Active,
    Sealed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SegmentMetadata {
    pub(super) scope: SegmentScope,
    pub(super) id: SegmentId,
    pub(super) state: SegmentState,
    pub(super) base_position: CommitPosition,
}

pub(super) struct SegmentHeader<'a> {
    pub(super) metadata: SegmentMetadata,
    pub(super) wrapped_key: &'a [u8],
    pub(super) encoded_bytes: usize,
}

pub(super) fn encode_metadata(metadata: SegmentMetadata) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(METADATA_BYTES);
    bytes.extend_from_slice(METADATA_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(match metadata.state {
        SegmentState::Active => 1,
        SegmentState::Sealed => 2,
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
    if bytes.len() != METADATA_BYTES || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice()) {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let state = match bytes.get(10).copied() {
        Some(1) => SegmentState::Active,
        Some(2) => SegmentState::Sealed,
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
    metadata: SegmentMetadata,
    wrapped_key: &[u8],
) -> Result<Vec<u8>, LedgerFailure> {
    if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let length = u32::try_from(wrapped_key.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let mut bytes = Vec::with_capacity(HEADER_PREFIX_BYTES + wrapped_key.len());
    bytes.extend_from_slice(SEGMENT_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&encode_metadata(metadata));
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(wrapped_key);
    Ok(bytes)
}

pub(super) fn decode_header(bytes: &[u8]) -> Result<SegmentHeader<'_>, LedgerFailure> {
    if bytes.get(..8) != Some(SEGMENT_MAGIC.as_slice())
        || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
    {
        return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
    }
    let metadata = decode_metadata(
        bytes
            .get(10..10 + METADATA_BYTES)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
    )?
    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    let wrapped_length = usize::try_from(u32::from_be_bytes(exact(bytes, 10 + METADATA_BYTES, 4)?))
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if wrapped_length == 0 || wrapped_length > MAX_WRAPPED_KEY_BYTES {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let encoded_bytes = HEADER_PREFIX_BYTES
        .checked_add(wrapped_length)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let wrapped_key = bytes
        .get(HEADER_PREFIX_BYTES..encoded_bytes)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
    Ok(SegmentHeader {
        metadata,
        wrapped_key,
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
