use super::session::{PendingBatch, TailSession};
use crate::memory::QueryMemory;
use crate::result_key::HistoricalTotalKey;
use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode, QueryRecord};

impl<'service, 'kernel, 'catalog, 'ledger> TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) fn deliver_records(
        &mut self,
        records: Vec<QueryRecord>,
        positions: Vec<super::TailPosition>,
        historical_complete: bool,
        historical_key: Option<HistoricalTotalKey>,
    ) -> Result<(), QueryFailure> {
        let rows = u64::try_from(records.len())
            .map_err(|_| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
        let bytes = crate::execution_support::output_bytes_for_records(
            self.service,
            &records,
            &mut self.cpu_work_units,
            self.query.budget.cpu_work_units(),
            &self.query.cancellation,
        )?;
        self.checked_output_totals(rows, bytes)?;
        let mut digest_memory = QueryMemory::new(self.runtime_memory_limit);
        let mut digest_observer = crate::execution_support::QueryValueObserver::new(
            self.service,
            &mut self.cpu_work_units,
            self.query.budget.cpu_work_units(),
            self.query.cancellation.clone(),
            crate::QueryWorkStage::Output,
        );
        let digest = crate::execution_support::batch_digest(
            &self.service.ledger.control_tokens(),
            crate::execution_support::BatchDigestInput {
                prior: self.prior_digest,
                sequence: self.next_sequence,
                plan: &self.query.plan,
                records: &records,
                cancellation: &self.query.cancellation,
                observer: &mut digest_observer,
            },
            &mut digest_memory,
        )?;
        self.record_memory_peak(digest_memory.peak())?;
        if let Err(failure) = self.buffer.push(records) {
            if failure.code() == QueryFailureCode::ResourceAdmissionRefused {
                self.terminal_after_progress_failure(super::TailTerminal::ConsumerLagged {
                    cursor: Some(self.cursor.clone()),
                    stats: self.terminal_stats(),
                });
                return Ok(());
            }
            return Err(failure);
        }
        self.record_memory_peak(self.buffer.memory_peak())?;
        self.pending_batch = Some(PendingBatch {
            positions,
            digest,
            rows,
            bytes,
            historical_complete,
            historical_key,
        });
        self.publish_delivery_cursor(digest)?;
        Ok(())
    }
}
