use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};

use super::format::position_from_value;
use super::snapshot_lease_record::{
    LeaseBlock, LeaseRecord, SnapshotLeaseId, valid_lease_interval,
};
use super::{
    CommittedBlock, LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope, StoreBlockIdentity,
};

const LEASE_MAGIC: [u8; 8] = *b"PSLEASE1";
const LEASE_VERSION: u16 = 2;
const LEASE_MARKER_VERSION: u16 = 3;
const LEASE_V1_HEADER_BYTES: usize = 105;
const LEASE_V2_HEADER_BYTES: usize = 113;
const LEASE_HEADER_BYTES: usize = 169;
const LEASE_BLOCK_BYTES: usize = 40;

pub(super) fn encode(record: &LeaseRecord) -> Result<Vec<u8>, LedgerFailure> {
    if record.blocks.len() > super::MAX_RETAINED_BLOCKS
        || !valid_lease_interval(record.observed_at, record.expiry)
    {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let mut bytes =
        Vec::with_capacity(LEASE_HEADER_BYTES + record.blocks.len() * LEASE_BLOCK_BYTES);
    bytes.extend_from_slice(&LEASE_MAGIC);
    let version = if record.resume_count > 0 || record.last_resume_sequence.is_some() {
        LEASE_MARKER_VERSION
    } else {
        LEASE_VERSION
    };
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&record.identity.to_bytes());
    bytes.extend_from_slice(&record.scope.tenant.to_bytes());
    bytes.push(signal_tag(record.scope.signal));
    bytes.extend_from_slice(&record.scope.shard.value().to_be_bytes());
    bytes.extend_from_slice(&record.catalog_identity.to_bytes());
    bytes.extend_from_slice(&record.catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&record.frontier.value().to_be_bytes());
    bytes.extend_from_slice(&record.observed_at.to_be_bytes());
    bytes.extend_from_slice(&record.expiry.to_be_bytes());
    if version == LEASE_MARKER_VERSION {
        bytes.extend_from_slice(&record.resume_count.to_be_bytes());
        bytes.extend_from_slice(&record.repeated_batch_count.to_be_bytes());
        bytes.extend_from_slice(
            &record
                .last_resume_sequence
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&record.last_resume_prior_digest);
    }
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
    let version = u16::from_be_bytes(exact(bytes, 8)?);
    let (header_bytes, count_offset) = match version {
        1 => (LEASE_V1_HEADER_BYTES, 103),
        2 => (LEASE_V2_HEADER_BYTES, 111),
        LEASE_MARKER_VERSION => (LEASE_HEADER_BYTES, 167),
        _ => return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption)),
    };
    let count = usize::from(u16::from_be_bytes(exact(bytes, count_offset)?));
    let expected = header_bytes
        .checked_add(
            count
                .checked_mul(LEASE_BLOCK_BYTES)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
        )
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if bytes.len() != expected || count > super::MAX_RETAINED_BLOCKS {
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
        let start = header_bytes + index * LEASE_BLOCK_BYTES;
        blocks.push(LeaseBlock {
            identity: StoreBlockIdentity::new(exact(bytes, start)?)?,
            position: position_from_value(u64::from_be_bytes(exact(bytes, start + 16)?))?,
            segment: SegmentId::new(exact(bytes, start + 24)?)?,
        });
    }
    let observed_at = if version == 1 {
        0
    } else {
        u64::from_be_bytes(exact(bytes, 95)?)
    };
    let expiry = u64::from_be_bytes(exact(bytes, if version == 1 { 95 } else { 103 })?);
    if version != 1 && !valid_lease_interval(observed_at, expiry) {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    let (resume_count, repeated_batch_count, last_resume_sequence, last_resume_prior_digest) =
        if version == LEASE_MARKER_VERSION {
            let resume_count = u64::from_be_bytes(exact(bytes, 111)?);
            let repeated_batch_count = u64::from_be_bytes(exact(bytes, 119)?);
            let sequence = u64::from_be_bytes(exact(bytes, 127)?);
            if repeated_batch_count > resume_count
                || (resume_count == 0 && sequence != u64::MAX)
                || (resume_count > 0 && sequence == u64::MAX)
            {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            }
            (
                resume_count,
                repeated_batch_count,
                (sequence != u64::MAX).then_some(sequence),
                exact(bytes, 135)?,
            )
        } else {
            (0, 0, None, [0; 32])
        };
    Ok(Some(LeaseRecord {
        identity: SnapshotLeaseId::new(exact(bytes, 10)?)?,
        scope,
        catalog_identity: crate::CatalogGenerationId::from_authenticated_bytes(exact(bytes, 47)?),
        catalog_generation: u64::from_be_bytes(exact(bytes, 79)?),
        frontier: position_from_value(u64::from_be_bytes(exact(bytes, 87)?))?,
        observed_at,
        expiry,
        resume_count,
        repeated_batch_count,
        last_resume_sequence,
        last_resume_prior_digest,
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

#[cfg(test)]
mod tests {
    use super::{LEASE_MAGIC, decode};
    use crate::active_segment_ledger::LedgerFailureCode;

    #[test]
    fn unknown_snapshot_lease_version_fails_closed() {
        let mut bytes = LEASE_MAGIC.to_vec();
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            decode(&bytes)
                .err()
                .expect("unknown snapshot lease versions must fail closed")
                .code(),
            LedgerFailureCode::IntegrityCorruption
        );
    }
}
