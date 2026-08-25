use std::cell::Cell;

use positron_signals::{ScanObservationFailureCode, ScanObserver};

use crate::cursor::CursorState;
use crate::{QueryCancellation, QueryWorkMeter, QueryWorkStage};

/// Query adapter for the Signal Store's query-agnostic validate-only work observer.
pub(crate) struct QueryScanObserver<'a> {
    work_meter: &'a dyn QueryWorkMeter,
    cancellation: QueryCancellation,
    consumed: Cell<u64>,
    cpu_limit: u64,
    scanned_bytes: Cell<u64>,
    scanned_bytes_limit: u64,
    decoded_records: Cell<u64>,
    decoded_records_limit: u64,
}

impl<'a> QueryScanObserver<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        work_meter: &'a dyn QueryWorkMeter,
        cancellation: QueryCancellation,
        consumed_cpu: u64,
        cpu_limit: u64,
        scanned_bytes: u64,
        scanned_bytes_limit: u64,
        decoded_records: u64,
        decoded_records_limit: u64,
    ) -> Self {
        Self {
            work_meter,
            cancellation,
            consumed: Cell::new(consumed_cpu),
            cpu_limit,
            scanned_bytes: Cell::new(scanned_bytes),
            scanned_bytes_limit,
            decoded_records: Cell::new(decoded_records),
            decoded_records_limit,
        }
    }

    pub(crate) const fn consumed(&self) -> u64 {
        self.consumed.get()
    }

    pub(crate) const fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes.get()
    }

    pub(crate) const fn decoded_records(&self) -> u64 {
        self.decoded_records.get()
    }

    pub(crate) fn harvest(&self, state: &mut CursorState) {
        state.physical_scanned_bytes = self.scanned_bytes();
        state.physical_decoded_records = self.decoded_records();
        state.physical_cpu_work_units = self.consumed();
    }

    fn observe_stage(
        &self,
        stage: QueryWorkStage,
        units: u64,
    ) -> Result<(), ScanObservationFailureCode> {
        if self.cancellation.is_cancelled() {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        let unit_cost = self
            .work_meter
            .units(stage)
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
        if consumed > self.cpu_limit {
            return Err(ScanObservationFailureCode::BudgetExhausted);
        }
        Ok(())
    }

    fn observe_progress(
        &self,
        progress: &Cell<u64>,
        amount: u64,
        limit: u64,
    ) -> Result<(), ScanObservationFailureCode> {
        let next = progress
            .get()
            .checked_add(amount)
            .ok_or(ScanObservationFailureCode::BudgetExhausted)?;
        if next > limit {
            return Err(ScanObservationFailureCode::BudgetExhausted);
        }
        progress.set(next);
        Ok(())
    }
}

impl ScanObserver for QueryScanObserver<'_> {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        self.observe_stage(QueryWorkStage::ScanDecode, units)
    }

    fn observe_scanned_bytes(&self, bytes: u64) -> Result<(), ScanObservationFailureCode> {
        if self.cancellation.is_cancelled() {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        self.observe_progress(&self.scanned_bytes, bytes, self.scanned_bytes_limit)
    }

    fn observe_decoded_records(&self, records: u64) -> Result<(), ScanObservationFailureCode> {
        self.observe_progress(&self.decoded_records, records, self.decoded_records_limit)?;
        if self.cancellation.is_cancelled() {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        Ok(())
    }
}

impl positron_domain::value::NativeValueObserver for QueryScanObserver<'_> {
    type Error = ScanObservationFailureCode;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        self.observe_stage(QueryWorkStage::Operators, 1)
    }

    fn observe_payload(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        if payload.len() > positron_domain::value::NATIVE_VALUE_PAYLOAD_CHUNK_BYTES {
            return Err(ScanObservationFailureCode::Internal);
        }
        if self.cancellation.is_cancelled() {
            Err(ScanObservationFailureCode::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Meter;

    impl QueryWorkMeter for Meter {
        fn units(&self, _stage: QueryWorkStage) -> Result<u64, crate::QueryWorkFailure> {
            Ok(1)
        }
    }

    #[test]
    fn progress_events_are_checked_and_harvested_without_cpu_double_charge() {
        let meter = Meter;
        let observer = QueryScanObserver::new(&meter, QueryCancellation::new(), 3, 10, 4, 8, 1, 2);
        assert_eq!(observer.consumed(), 3);
        observer
            .observe_scanned_bytes(4)
            .expect("admitted block bytes fit");
        observer
            .observe_decoded_records(1)
            .expect("decoded record fits");
        assert_eq!(observer.scanned_bytes(), 8);
        assert_eq!(observer.decoded_records(), 2);
        assert_eq!(observer.consumed(), 3);
        assert_eq!(
            observer
                .observe_scanned_bytes(1)
                .expect_err("scanned byte ceiling is hard"),
            ScanObservationFailureCode::BudgetExhausted
        );
        assert_eq!(
            observer
                .observe_decoded_records(1)
                .expect_err("decoded record ceiling is hard"),
            ScanObservationFailureCode::BudgetExhausted
        );
    }
}
