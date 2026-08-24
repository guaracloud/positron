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

/// Bounded delivery marker owned by the Snapshot Lease authority.
///
/// Query cursors are opaque immutable values, so the lease is the one place
/// that can distinguish a first resume of a cursor from a retry after an
/// ambiguous batch delivery. This state is deliberately bounded to one
/// marker per active lease and is not a second query scheduler or cursor
/// authority.
#[derive(Clone, Copy, Default)]
pub(super) struct LeaseResumeMarker {
    pub(super) sequence: u64,
    pub(super) prior_digest: [u8; 32],
    pub(super) attempts: u64,
    pub(super) repeats: u64,
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
    pub(super) resume_count: u64,
    pub(super) repeated_batch_count: u64,
    pub(super) last_resume_sequence: Option<u64>,
    pub(super) last_resume_prior_digest: [u8; 32],
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

#[cfg(test)]
mod tests {
    use positron_domain::identity::TenantId;
    use positron_domain::routing::{SignalKind, VirtualShardId};

    use super::{LeaseRecord, SnapshotLeaseId, validate_active_lease};
    use crate::CatalogGenerationId;
    use crate::active_segment_ledger::SegmentScope;
    use positron_domain::routing::CommitPosition;

    fn record(observed_at: u64, expiry: u64) -> LeaseRecord {
        LeaseRecord {
            identity: SnapshotLeaseId::new([1; 16]).expect("nonzero lease identity"),
            scope: SegmentScope::new(
                TenantId::from_bytes([2; 16]).expect("tenant"),
                SignalKind::Logs,
                VirtualShardId::new(1).expect("shard"),
            ),
            catalog_identity: CatalogGenerationId::from_authenticated_bytes([3; 32]),
            catalog_generation: 1,
            frontier: CommitPosition::origin(),
            observed_at,
            expiry,
            resume_count: 0,
            repeated_batch_count: 0,
            last_resume_sequence: None,
            last_resume_prior_digest: [0; 32],
            blocks: Vec::new(),
        }
    }

    #[test]
    fn active_lease_validation_allows_expiry_and_rejects_clock_regression() {
        assert!(validate_active_lease(&record(100, 200), 200).is_ok());
        assert_eq!(
            validate_active_lease(&record(100, 200), 99)
                .expect_err("clock regression must be rejected")
                .code(),
            super::super::LedgerFailureCode::InvalidInput
        );

        let invalid_interval = record(100, 100);
        assert_eq!(
            super::super::snapshot_lease_codec::encode(&invalid_interval)
                .expect_err("zero-length lease interval must not be encoded")
                .code(),
            super::super::LedgerFailureCode::LimitExceeded
        );

        let mut invalid_marker = record(100, 200);
        invalid_marker.resume_count = 1;
        invalid_marker.last_resume_sequence = Some(1);
        invalid_marker.repeated_batch_count = 2;
        let mut encoded = super::super::snapshot_lease_codec::encode(&invalid_marker)
            .expect("valid marker shape");
        encoded[119..127].copy_from_slice(&2_u64.to_be_bytes());
        assert_eq!(
            super::super::snapshot_lease_codec::decode(&encoded)
                .err()
                .expect("contradictory marker counters must fail closed")
                .code(),
            super::super::LedgerFailureCode::IntegrityCorruption
        );
    }
}
