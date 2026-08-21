use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_kernel::ResourceReservation;

use super::{LogStoreFailure, StoredLogRecord};

const MAX_SCAN_RECORDS: usize = 1_024;

/// Cooperative cancellation capability for bounded Signal Store scans.
pub trait ScanCancellation: Send + Sync {
    /// Reports whether the caller has cancelled the scan.
    fn is_cancelled(&self) -> bool;
}

/// Stable caller-owned failure from bounded scan work observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanObservationFailureCode {
    BudgetExhausted,
    Cancelled,
    ResourceExhausted,
    Internal,
}

/// Query-agnostic capability for accounting bounded Signal Store scan work.
pub trait ScanObserver {
    /// Accounts deterministic bounded decode operations. Raw payload volume is
    /// accounted separately by `scanned_bytes` and is never duplicated here.
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode>;
}

pub(super) struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

pub(super) struct Unobserved;

impl ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
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
    retained_size_bytes: u64,
    reduced_pruning: bool,
    _capacity: ResourceReservation<'kernel>,
}

impl<'kernel> LogScanResult<'kernel> {
    pub(super) const fn new(
        records: Vec<ScannedLogRecord>,
        complete: bool,
        scanned_bytes: u64,
        retained_size_bytes: u64,
        reduced_pruning: bool,
        capacity: ResourceReservation<'kernel>,
    ) -> Self {
        Self {
            records,
            complete,
            scanned_bytes,
            retained_size_bytes,
            reduced_pruning,
            _capacity: capacity,
        }
    }

    #[must_use]
    pub fn records(&self) -> &[ScannedLogRecord] {
        &self.records
    }

    /// Consumes the scan container and transfers ownership of its verified records.
    #[must_use]
    pub fn into_records(self) -> Vec<ScannedLogRecord> {
        self.records
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    /// Returns the canonical conservative bytes retained by the decoded result.
    #[must_use]
    pub const fn retained_size_bytes(&self) -> u64 {
        self.retained_size_bytes
    }

    /// Reports that generic or Schema Overflow records required fallback decoding.
    #[must_use]
    pub const fn reduced_pruning(&self) -> bool {
        self.reduced_pruning
    }
}

/// One verified log plus its stable logical identity.
///
/// `(commit_position, record_ordinal)` is assigned from the authenticated
/// original Store Block and must survive physical compaction unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedLogRecord {
    record: StoredLogRecord,
    commit_position: CommitPosition,
    record_ordinal: RecordOrdinal,
    body_retained_bytes: u64,
}

impl ScannedLogRecord {
    pub(super) const fn new(
        record: StoredLogRecord,
        commit_position: CommitPosition,
        record_ordinal: RecordOrdinal,
    ) -> Self {
        Self {
            record,
            commit_position,
            record_ordinal,
            body_retained_bytes: 0,
        }
    }

    #[must_use]
    pub const fn stored(&self) -> &StoredLogRecord {
        &self.record
    }

    /// Transfers the optional native body out of this query-owned scan record.
    pub fn take_body(&mut self) -> Option<positron_domain::value::ValidatedAttributeValue> {
        self.record.take_body()
    }

    /// Returns the scan-accounted heap bytes transferred with the native body.
    #[must_use]
    pub const fn body_retained_bytes(&self) -> u64 {
        self.body_retained_bytes
    }

    pub(super) fn set_body_retained_bytes(&mut self, bytes: u64) {
        self.body_retained_bytes = bytes;
    }

    #[must_use]
    pub const fn commit_position(&self) -> CommitPosition {
        self.commit_position
    }

    /// Returns the record's position in its original authenticated Store Block.
    #[must_use]
    pub const fn record_ordinal(&self) -> RecordOrdinal {
        self.record_ordinal
    }
}

impl std::ops::Deref for ScannedLogRecord {
    type Target = StoredLogRecord;

    fn deref(&self) -> &Self::Target {
        &self.record
    }
}
