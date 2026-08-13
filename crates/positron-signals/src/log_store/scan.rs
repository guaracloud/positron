use positron_kernel::ResourceReservation;

use super::{LogStoreFailure, StoredLogRecord};

const MAX_SCAN_RECORDS: usize = 1_024;

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
}

impl LogScan {
    #[must_use]
    pub const fn all(limit: ScanLimit) -> Self {
        Self { limit }
    }

    #[must_use]
    pub const fn limit(self) -> ScanLimit {
        self.limit
    }
}

/// A bounded logical result that holds its query capacity until drop.
#[derive(Debug)]
pub struct LogScanResult<'kernel> {
    records: Vec<StoredLogRecord>,
    complete: bool,
    _capacity: ResourceReservation<'kernel>,
}

impl<'kernel> LogScanResult<'kernel> {
    pub(super) const fn new(
        records: Vec<StoredLogRecord>,
        complete: bool,
        capacity: ResourceReservation<'kernel>,
    ) -> Self {
        Self {
            records,
            complete,
            _capacity: capacity,
        }
    }

    #[must_use]
    pub fn records(&self) -> &[StoredLogRecord] {
        &self.records
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
}
