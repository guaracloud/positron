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

    /// Accounts an authenticated block payload admitted for physical scan.
    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    /// Accounts a record after canonical decode and validation succeeded.
    fn observe_decoded_records(&self, _records: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
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

impl positron_domain::value::NativeValueObserver for Unobserved {
    type Error = ScanObservationFailureCode;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
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
    after: Option<CommitPosition>,
    after_record: Option<(CommitPosition, RecordOrdinal)>,
    frontier: Option<CommitPosition>,
    scanned_bytes: Option<u64>,
}

impl LogScan {
    #[must_use]
    pub const fn all(limit: ScanLimit) -> Self {
        Self {
            limit,
            after: None,
            after_record: None,
            frontier: None,
            scanned_bytes: None,
        }
    }

    #[must_use]
    pub const fn through(limit: ScanLimit, frontier: CommitPosition) -> Self {
        Self {
            limit,
            after: None,
            after_record: None,
            frontier: Some(frontier),
            scanned_bytes: None,
        }
    }

    /// Returns committed blocks strictly after `position` and up to the
    /// current snapshot frontier. The lower bound is a commit position, never
    /// a timestamp, so a tail handoff cannot skip a commit made at the same
    /// source time.
    #[must_use]
    pub const fn after(limit: ScanLimit, position: CommitPosition) -> Self {
        Self {
            limit,
            after: Some(position),
            after_record: None,
            frontier: None,
            scanned_bytes: None,
        }
    }

    /// Returns committed blocks in the exclusive/inclusive interval
    /// `(after, frontier]`.
    #[must_use]
    pub const fn between(
        limit: ScanLimit,
        after: CommitPosition,
        frontier: CommitPosition,
    ) -> Self {
        Self {
            limit,
            after: Some(after),
            after_record: None,
            frontier: Some(frontier),
            scanned_bytes: None,
        }
    }

    /// Returns committed records strictly after one stable record identity and
    /// up to the current snapshot frontier. The containing block remains in
    /// the scan so the decoder can structurally skip the already delivered
    /// prefix without losing records that share its commit position.
    #[must_use]
    pub const fn between_record(
        limit: ScanLimit,
        position: CommitPosition,
        ordinal: RecordOrdinal,
        frontier: CommitPosition,
    ) -> Self {
        Self {
            limit,
            after: None,
            after_record: Some((position, ordinal)),
            frontier: Some(frontier),
            scanned_bytes: None,
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

    #[must_use]
    pub const fn after_position(self) -> Option<CommitPosition> {
        self.after
    }

    #[must_use]
    pub const fn after_record(self) -> Option<(CommitPosition, RecordOrdinal)> {
        self.after_record
    }

    /// Applies the cumulative raw-payload ceiling to this scan. The Signal
    /// Store checks this limit before authenticated block metadata, index, or
    /// decode work, so an atomic block that cannot fit contributes no work or
    /// result prefix.
    #[must_use]
    pub const fn with_scanned_bytes(self, limit: u64) -> Self {
        Self {
            limit: self.limit,
            after: self.after,
            after_record: self.after_record,
            frontier: self.frontier,
            scanned_bytes: Some(limit),
        }
    }

    #[must_use]
    pub const fn scanned_bytes_limit(self) -> Option<u64> {
        self.scanned_bytes
    }
}

pub(super) fn admit_block_bytes(
    scanned_bytes: u64,
    block_bytes: usize,
    limit: Option<u64>,
) -> Result<Option<u64>, LogStoreFailure> {
    let block_bytes = u64::try_from(block_bytes).map_err(|_| LogStoreFailure::limit_exceeded())?;
    let next = scanned_bytes
        .checked_add(block_bytes)
        .ok_or_else(LogStoreFailure::limit_exceeded)?;
    if limit.is_some_and(|limit| next > limit) {
        Ok(None)
    } else {
        Ok(Some(next))
    }
}

pub(super) fn includes_block(scan: LogScan, position: CommitPosition) -> bool {
    (if let Some((after, _)) = scan.after_record() {
        position >= after
    } else {
        scan.after_position().is_none_or(|after| position > after)
    }) && scan.frontier().is_none_or(|frontier| position <= frontier)
}

pub(super) fn skipped_records(scan: LogScan, position: CommitPosition) -> usize {
    scan.after_record()
        .filter(|(after, _)| *after == position)
        .and_then(|(_, ordinal)| usize::from(ordinal.value()).checked_add(1))
        .unwrap_or(0)
}

/// A bounded logical result that holds its query capacity until drop.
#[derive(Debug)]
pub struct LogScanResult<'kernel> {
    records: Vec<ScannedLogRecord>,
    decoded_records: u64,
    complete: bool,
    scanned_bytes: u64,
    scanned_bytes_limited: bool,
    retained_size_bytes: u64,
    reduced_pruning: bool,
    _capacity: ResourceReservation<'kernel>,
}

impl<'kernel> LogScanResult<'kernel> {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        records: Vec<ScannedLogRecord>,
        decoded_records: u64,
        complete: bool,
        scanned_bytes: u64,
        scanned_bytes_limited: bool,
        retained_size_bytes: u64,
        reduced_pruning: bool,
        capacity: ResourceReservation<'kernel>,
    ) -> Self {
        Self {
            records,
            decoded_records,
            complete,
            scanned_bytes,
            scanned_bytes_limited,
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

    /// Returns every authenticated record decoded during this scan, including
    /// records rejected by a schema predicate.
    #[must_use]
    pub const fn decoded_records(&self) -> u64 {
        self.decoded_records
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }

    #[must_use]
    pub const fn scanned_bytes_limited(&self) -> bool {
        self.scanned_bytes_limited
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
