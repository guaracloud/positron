use positron_domain::routing::CommitPosition;

use super::{LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope, StoreBlockIdentity};

/// Release 1 hard system ceiling for one Snapshot Lease lifetime.
///
/// This is deliberately compiled rather than configurable in Release 1 so
/// Query Budget admission and durable lease validation share one authority.
pub const MAX_SNAPSHOT_LEASE_TTL_SECONDS: u64 = 3_600;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotLeaseId([u8; 16]);

impl SnapshotLeaseId {
    pub fn new(bytes: [u8; 16]) -> Result<Self, LedgerFailure> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone)]
pub(super) struct LeaseRecord {
    pub(super) identity: SnapshotLeaseId,
    pub(super) scope: SegmentScope,
    pub(super) catalog_identity: crate::CatalogGenerationId,
    pub(super) catalog_generation: u64,
    pub(super) frontier: CommitPosition,
    pub(super) observed_at: u64,
    pub(super) expiry: u64,
    pub(super) blocks: Vec<LeaseBlock>,
}

#[derive(Clone, Copy)]
pub(super) struct LeaseBlock {
    pub(super) identity: StoreBlockIdentity,
    pub(super) position: CommitPosition,
    pub(super) segment: SegmentId,
}

pub(super) fn valid_lease_interval(observed_at: u64, expiry: u64) -> bool {
    expiry
        .checked_sub(observed_at)
        .is_some_and(|ttl| (1..=MAX_SNAPSHOT_LEASE_TTL_SECONDS).contains(&ttl))
}

pub(super) fn validate_active_lease(record: &LeaseRecord, now: u64) -> Result<(), LedgerFailure> {
    if now >= record.expiry {
        return Ok(());
    }
    if record.observed_at != 0 && now < record.observed_at {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    if record
        .expiry
        .checked_sub(now)
        .is_none_or(|remaining| remaining > MAX_SNAPSHOT_LEASE_TTL_SECONDS)
    {
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    Ok(())
}
