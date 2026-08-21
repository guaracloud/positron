use std::cell::Cell;

use positron_signals::{ScanObservationFailureCode, ScanObserver};

use crate::{QueryCancellation, QueryWorkMeter, QueryWorkStage};

/// Query adapter for the Signal Store's query-agnostic validate-only work observer.
pub(crate) struct QueryScanObserver<'a> {
    work_meter: &'a dyn QueryWorkMeter,
    cancellation: QueryCancellation,
    consumed: Cell<u64>,
    limit: u64,
}

impl<'a> QueryScanObserver<'a> {
    pub(crate) const fn new(
        work_meter: &'a dyn QueryWorkMeter,
        cancellation: QueryCancellation,
        consumed: u64,
        limit: u64,
    ) -> Self {
        Self {
            work_meter,
            cancellation,
            consumed: Cell::new(consumed),
            limit,
        }
    }

    pub(crate) const fn consumed(&self) -> u64 {
        self.consumed.get()
    }
}

impl ScanObserver for QueryScanObserver<'_> {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        if self.cancellation.is_cancelled() {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        let unit_cost = self
            .work_meter
            .units(QueryWorkStage::ScanDecode)
            .map_err(|_| ScanObservationFailureCode::Internal)?;
        let work = units
            .checked_mul(unit_cost)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        let consumed = self
            .consumed
            .get()
            .checked_add(work)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        self.consumed.set(consumed);
        if consumed > self.limit {
            return Err(ScanObservationFailureCode::BudgetExhausted);
        }
        Ok(())
    }
}
