use std::cell::Cell;

use positron_kernel::AppendCancellation;
use positron_signals::{ScanObservationFailureCode, ScanObserver};

pub(crate) struct SchemaBuildObserver<'a> {
    limit: u64,
    consumed: Cell<u64>,
    cancellation: Option<&'a AppendCancellation>,
}

impl<'a> SchemaBuildObserver<'a> {
    pub(crate) const fn new(limit: u64, cancellation: Option<&'a AppendCancellation>) -> Self {
        Self {
            limit,
            consumed: Cell::new(0),
            cancellation,
        }
    }
}

impl ScanObserver for SchemaBuildObserver<'_> {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        if self
            .cancellation
            .is_some_and(AppendCancellation::is_cancelled)
        {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        let consumed = self
            .consumed
            .get()
            .checked_add(units)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        self.consumed.set(consumed);
        if consumed > self.limit {
            Err(ScanObservationFailureCode::BudgetExhausted)
        } else {
            Ok(())
        }
    }
}
