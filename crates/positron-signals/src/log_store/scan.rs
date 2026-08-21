use positron_domain::routing::CommitPosition;
use positron_kernel::ResourceReservation;

use super::{LogStoreFailure, StoredLogRecord};

const MAX_SCAN_RECORDS: usize = 1_024;

/// Cooperative cancellation capability for bounded Signal Store scans.
pub trait ScanCancellation: Send + Sync {
    /// Reports whether the caller has cancelled the scan.
    fn is_cancelled(&self) -> bool;
}

pub(super) struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Explicit finite record bound for one logical scan result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLimit(usize);

impl ScanLimit {
    pub fn new(value: usize) -> Result<Self, LogStoreFailure> {
        if value == 0 || value > MAX_SCAN_RECORDS {
            return Err(LogStoreFailure::limit_exceeded());
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn value(self) -> usize {
        self.0
    }
}

/// The minimal M1 full logical scan request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogScan {
    limit: ScanLimit,
    frontier: Option<CommitPosition>,
}

impl LogScan {
    #[must_use]
    pub const fn all(limit: ScanLimit) -> Self {
        Self {
            limit,
            frontier: None,
        }
    }

    #[must_use]
    pub const fn through(limit: ScanLimit, frontier: CommitPosition) -> Self {
        Self {
            limit,
            frontier: Some(frontier),
        }
    }

    #[must_use]
    pub const fn limit(self) -> ScanLimit {
        self.limit
    }

    #[must_use]
    pub const fn frontier(self) -> Option<CommitPosition> {
        self.frontier
    }
}

/// A bounded logical result that holds its query capacity until drop.
#[derive(Debug)]
pub struct LogScanResult<'kernel> {
    records: Vec<ScannedLogRecord>,
    complete: bool,
    scanned_bytes: u64,
    reduced_pruning: bool,
    _capacity: ResourceReservation<'kernel>,
}

impl<'kernel> LogScanResult<'kernel> {
    pub(super) const fn new(
        records: Vec<ScannedLogRecord>,
        complete: bool,
        scanned_bytes: u64,
        reduced_pruning: bool,
        capacity: ResourceReservation<'kernel>,
    ) -> Self {
        Self {
            records,
            complete,
            scanned_bytes,
            reduced_pruning,
            _capacity: capacity,
        }
    }

    #[must_use]
    pub fn records(&self) -> &[ScannedLogRecord] {
        &self.records
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    /// Reports that generic or Schema Overflow records required fallback decoding.
    #[must_use]
    pub const fn reduced_pruning(&self) -> bool {
        self.reduced_pruning
    }
}

/// One verified log plus the kernel-assigned position that totally orders it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedLogRecord {
    record: StoredLogRecord,
    commit_position: CommitPosition,
}

impl ScannedLogRecord {
    pub(super) const fn new(record: StoredLogRecord, commit_position: CommitPosition) -> Self {
        Self {
            record,
            commit_position,
        }
    }

    #[must_use]
    pub const fn stored(&self) -> &StoredLogRecord {
        &self.record
    }

    #[must_use]
    pub const fn commit_position(&self) -> CommitPosition {
        self.commit_position
    }
}

impl std::ops::Deref for ScannedLogRecord {
    type Target = StoredLogRecord;

    fn deref(&self) -> &Self::Target {
        &self.record
    }
}
