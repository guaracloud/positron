use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::format::position_from_value;
use super::snapshot_lease::{LeaseBlock, LeaseRecord, SnapshotLeaseId};
use super::{
    CommittedBlock, LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope, StoreBlockIdentity,
};

const LEASE_MAGIC: [u8; 8] = *b"PSLEASE1";
const LEASE_VERSION: u16 = 1;
const LEASE_HEADER_BYTES: usize = 105;
const LEASE_BLOCK_BYTES: usize = 40;

pub(super) fn encode(record: &LeaseRecord) -> Result<Vec<u8>, LedgerFailure> {
    if record.blocks.len() > super::MAX_RETAINED_BLOCKS {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let mut bytes =
        Vec::with_capacity(LEASE_HEADER_BYTES + record.blocks.len() * LEASE_BLOCK_BYTES);
    bytes.extend_from_slice(&LEASE_MAGIC);
    bytes.extend_from_slice(&LEASE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&record.identity.to_bytes());
    bytes.extend_from_slice(&record.scope.tenant.to_bytes());
    bytes.push(signal_tag(record.scope.signal));
    bytes.extend_from_slice(&record.scope.shard.value().to_be_bytes());
    bytes.extend_from_slice(&record.catalog_identity.to_bytes());
    bytes.extend_from_slice(&record.catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&record.frontier.value().to_be_bytes());
    bytes.extend_from_slice(&record.expiry.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(record.blocks.len())
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?
            .to_be_bytes(),
    );
    for block in &record.blocks {
        bytes.extend_from_slice(&block.identity.to_bytes());
        bytes.extend_from_slice(&block.position.value().to_be_bytes());
        bytes.extend_from_slice(&block.segment.to_bytes());
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Option<LeaseRecord>, LedgerFailure> {
    if !bytes.starts_with(&LEASE_MAGIC) {
        return Ok(None);
    }
    let count = usize::from(u16::from_be_bytes(exact(bytes, 103)?));
    let expected = LEASE_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(LEASE_BLOCK_BYTES)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if bytes.len() != expected
        || exact::<2>(bytes, 8)? != LEASE_VERSION.to_be_bytes()
        || count > super::MAX_RETAINED_BLOCKS
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let scope = SegmentScope::new(
        TenantId::from_bytes(exact(bytes, 26)?)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        signal_from_tag(
            *bytes
                .get(42)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
        )?,
        VirtualShardId::new(u32::from_be_bytes(exact(bytes, 43)?))
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?,
    );
    let mut blocks = Vec::with_capacity(count);
    for index in 0..count {
        let start = LEASE_HEADER_BYTES + index * LEASE_BLOCK_BYTES;
        blocks.push(LeaseBlock {
            identity: StoreBlockIdentity::new(exact(bytes, start)?)?,
            position: position_from_value(u64::from_be_bytes(exact(bytes, start + 16)?))?,
            segment: SegmentId::new(exact(bytes, start + 24)?)?,
        });
    }
    Ok(Some(LeaseRecord {
        identity: SnapshotLeaseId::new(exact(bytes, 10)?)?,
        scope,
        catalog_identity: crate::CatalogGenerationId::from_authenticated_bytes(exact(bytes, 47)?),
        catalog_generation: u64::from_be_bytes(exact(bytes, 79)?),
        frontier: position_from_value(u64::from_be_bytes(exact(bytes, 87)?))?,
        expiry: u64::from_be_bytes(exact(bytes, 95)?),
        blocks,
    }))
}

fn exact<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], LedgerFailure> {
    bytes
        .get(start..start + N)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))
}

const fn signal_tag(signal: SignalKind) -> u8 {
    match signal {
        SignalKind::Logs => 1,
        SignalKind::Traces => 2,
    }
}

fn signal_from_tag(tag: u8) -> Result<SignalKind, LedgerFailure> {
    match tag {
        1 => Ok(SignalKind::Logs),
        2 => Ok(SignalKind::Traces),
        _ => Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    }
}

impl From<&CommittedBlock> for LeaseBlock {
    fn from(block: &CommittedBlock) -> Self {
        Self {
            identity: block.identity,
            position: block.position,
            segment: block.segment,
        }
    }
}
