use std::cell::Cell;

use positron_kernel::AppendCancellation;
use positron_signals::{ScanCancellation, ScanObservationFailureCode, ScanObserver};

pub(crate) struct SchemaBuildObserver<'a> {
    limit: u64,
    consumed: Cell<u64>,
    cancellation: Option<CancellationRef<'a>>,
}

enum CancellationRef<'a> {
    Append(&'a AppendCancellation),
    Scan(&'a dyn ScanCancellation),
}

impl<'a> SchemaBuildObserver<'a> {
    pub(crate) fn new(limit: u64, cancellation: Option<&'a AppendCancellation>) -> Self {
        Self {
            limit,
            consumed: Cell::new(0),
            cancellation: cancellation.map(CancellationRef::Append),
        }
    }

    pub(crate) const fn new_scan(limit: u64, cancellation: &'a dyn ScanCancellation) -> Self {
        Self {
            limit,
            consumed: Cell::new(0),
            cancellation: Some(CancellationRef::Scan(cancellation)),
        }
    }

    #[cfg(test)]
    pub(crate) const fn consumed(&self) -> u64 {
        self.consumed.get()
    }
}

impl ScanObserver for SchemaBuildObserver<'_> {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let cancelled = match self.cancellation {
            Some(CancellationRef::Append(cancellation)) => cancellation.is_cancelled(),
            Some(CancellationRef::Scan(cancellation)) => cancellation.is_cancelled(),
            None => false,
        };
        if cancelled {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        let consumed = self
            .consumed
            .get()
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        if consumed > self.limit {
            Err(ScanObservationFailureCode::BudgetExhausted)
        } else {
            self.consumed.set(consumed);
            Ok(())
        }
    }
}
