use positron_domain::routing::CommitPosition;

use super::{LedgerFailure, LedgerFailureCode, SegmentId, SegmentScope, StoreBlockIdentity};

#[derive(Clone, Copy)]
pub(super) struct LeaseWindow {
    pub(super) observed: u64,
    pub(super) expiry: u64,
}

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

/// Monotonic physical work charged to one durable snapshot lease.
///
/// Additive dimensions count every admitted attempt; memory is the maximum
/// live peak observed by the query. The value is fixed-size so durable lease
/// metadata remains bounded across retries and reconnects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnapshotLeaseUsage {
    scanned_bytes: u64,
    decoded_records: u64,
    cpu_work_units: u64,
    wall_seconds: u64,
    output_rows: u64,
    output_bytes: u64,
    memory_peak_bytes: u64,
}

impl SnapshotLeaseUsage {
    #[must_use]
    pub const fn new(
        scanned_bytes: u64,
        decoded_records: u64,
        cpu_work_units: u64,
        wall_seconds: u64,
        output_rows: u64,
        output_bytes: u64,
        memory_peak_bytes: u64,
    ) -> Self {
        Self {
            scanned_bytes,
            decoded_records,
            cpu_work_units,
            wall_seconds,
            output_rows,
            output_bytes,
            memory_peak_bytes,
        }
    }

    #[must_use]
    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn decoded_records(self) -> u64 {
        self.decoded_records
    }

    #[must_use]
    pub const fn cpu_work_units(self) -> u64 {
        self.cpu_work_units
    }

    #[must_use]
    pub const fn wall_seconds(self) -> u64 {
        self.wall_seconds
    }

    #[must_use]
    pub const fn output_rows(self) -> u64 {
        self.output_rows
    }

    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }

    #[must_use]
    pub const fn memory_peak_bytes(self) -> u64 {
        self.memory_peak_bytes
    }

    pub(super) fn merge(self, delta: Self) -> Result<Self, LedgerFailure> {
        Ok(Self {
            scanned_bytes: self
                .scanned_bytes
                .checked_add(delta.scanned_bytes)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            decoded_records: self
                .decoded_records
                .checked_add(delta.decoded_records)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            cpu_work_units: self
                .cpu_work_units
                .checked_add(delta.cpu_work_units)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            wall_seconds: self
                .wall_seconds
                .checked_add(delta.wall_seconds)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            output_rows: self
                .output_rows
                .checked_add(delta.output_rows)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            output_bytes: self
                .output_bytes
                .checked_add(delta.output_bytes)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            memory_peak_bytes: self.memory_peak_bytes.max(delta.memory_peak_bytes),
        })
    }

    #[must_use]
    pub(super) const fn is_zero(self) -> bool {
        self.scanned_bytes == 0
            && self.decoded_records == 0
            && self.cpu_work_units == 0
            && self.wall_seconds == 0
            && self.output_rows == 0
            && self.output_bytes == 0
            && self.memory_peak_bytes == 0
    }
}

/// Bounded delivery marker owned by the Snapshot Lease authority.
///
/// Query cursors are opaque immutable values, so the lease is the one place
/// that can distinguish a first resume of a cursor from a retry after an
/// ambiguous batch delivery. This state is deliberately bounded to one
/// marker per active lease and is not a second query scheduler or cursor
/// authority.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) struct LeaseResumeMarker {
    pub(super) sequence: u64,
    pub(super) prior_digest: [u8; 32],
    pub(super) attempts: u64,
    pub(super) repeats: u64,
    pub(super) usage: SnapshotLeaseUsage,
}

pub(super) fn resume_marker_for(record: &LeaseRecord) -> LeaseResumeMarker {
    LeaseResumeMarker {
        sequence: record.last_resume_sequence.unwrap_or_default(),
        prior_digest: record.last_resume_prior_digest,
        attempts: record.resume_count,
        repeats: record.repeated_batch_count,
        usage: record.usage,
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
    pub(super) resume_count: u64,
    pub(super) repeated_batch_count: u64,
    pub(super) last_resume_sequence: Option<u64>,
    pub(super) last_resume_prior_digest: [u8; 32],
    pub(super) usage: SnapshotLeaseUsage,
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

    use super::{LeaseRecord, SnapshotLeaseId, SnapshotLeaseUsage, validate_active_lease};
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
            usage: super::SnapshotLeaseUsage::default(),
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

    #[test]
    fn usage_merge_rejects_additive_counter_wrap_and_preserves_peak_semantics() {
        let overflowing = [
            SnapshotLeaseUsage::new(u64::MAX, 0, 0, 0, 0, 0, 0),
            SnapshotLeaseUsage::new(0, u64::MAX, 0, 0, 0, 0, 0),
            SnapshotLeaseUsage::new(0, 0, u64::MAX, 0, 0, 0, 0),
            SnapshotLeaseUsage::new(0, 0, 0, u64::MAX, 0, 0, 0),
            SnapshotLeaseUsage::new(0, 0, 0, 0, u64::MAX, 0, 0),
            SnapshotLeaseUsage::new(0, 0, 0, 0, 0, u64::MAX, 0),
        ];
        for current in overflowing {
            assert_eq!(
                current
                    .merge(SnapshotLeaseUsage::new(1, 1, 1, 1, 1, 1, 7))
                    .expect_err("additive usage must fail closed before wrapping")
                    .code(),
                super::super::LedgerFailureCode::LimitExceeded
            );
        }
        let merged = SnapshotLeaseUsage::new(1, 2, 3, 4, 5, 6, 9)
            .merge(SnapshotLeaseUsage::new(7, 8, 9, 10, 11, 12, 3))
            .expect("non-overflowing usage must merge");
        assert_eq!(merged.memory_peak_bytes(), 9);
        assert_eq!(merged.scanned_bytes(), 8);
        assert_eq!(merged.wall_seconds(), 14);
    }
}
