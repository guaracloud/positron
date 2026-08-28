use super::super::cursor::{TailCursor, TailPosition};
use super::{AdvancedBatch, TailSession};
use crate::result_key::HistoricalTotalKey;
use crate::{QueryBudgetDimension, QueryFailure};

impl<'service, 'kernel, 'catalog, 'ledger> TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) fn candidate_advance(
        &self,
        positions: Vec<TailPosition>,
        digest: [u8; 32],
        output_rows: u64,
        output_bytes: u64,
        historical_complete: bool,
        historical_key: Option<HistoricalTotalKey>,
    ) -> Result<AdvancedBatch<'kernel, 'catalog, 'ledger>, QueryFailure> {
        let mut state = self.state.clone();
        if historical_key.is_some() {
            state.set_historical_key(historical_key);
        }
        state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            output_rows,
            output_bytes,
            self.cpu_work_units,
        );
        state.set_runtime_stats(
            self.memory_peak_bytes,
            self.elapsed_seconds,
            self.reduced_pruning,
            self.limiting_budget,
        );
        let mut state = state.advance_batch(&positions, digest)?;
        if historical_complete {
            state = state.advance_positions(&self.historical_frontiers)?;
            state.set_record_bound(false);
            state.clear_historical_markers();
        }
        let lease_rotation = self.prepare_lease_rotation(&mut state, historical_complete)?;
        let cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &state)?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(super::super::internal)?;
        Ok(AdvancedBatch {
            state,
            cursor,
            prior_digest: digest,
            next_sequence,
            lease_rotation,
        })
    }

    pub(in crate::tail) fn advance_positions(
        &mut self,
        positions: &[TailPosition],
        clear_historical: bool,
    ) -> Result<(), QueryFailure> {
        self.sync_state_progress();
        let mut state = self.state.advance_positions(positions)?;
        if clear_historical {
            state.set_record_bound(false);
            state.clear_historical_markers();
        }
        let lease_rotation = self.prepare_lease_rotation(&mut state, clear_historical)?;
        let cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &state)?;
        self.commit_lease_rotation(lease_rotation)?;
        self.state = state;
        self.cursor = cursor;
        Ok(())
    }

    pub(in crate::tail) fn sync_progress(&mut self) -> Result<(), QueryFailure> {
        self.sync_state_progress();
        self.persist_lease_usage()?;
        self.cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &self.state)?;
        Ok(())
    }

    fn sync_state_progress(&mut self) {
        self.state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            self.output_rows,
            self.output_bytes,
            self.cpu_work_units,
        );
        self.state.set_runtime_stats(
            self.memory_peak_bytes,
            self.elapsed_seconds,
            self.reduced_pruning,
            self.limiting_budget,
        );
    }

    pub(in crate::tail) fn record_limiting_budget(&mut self, failure: &QueryFailure) {
        if let Some(dimension) = failure.limiting_budget() {
            self.limiting_budget = Some(dimension);
        }
    }

    pub(in crate::tail) fn checked_output_totals(
        &self,
        rows: u64,
        bytes: u64,
    ) -> Result<(u64, u64), QueryFailure> {
        let output_rows = self
            .output_rows
            .checked_add(rows)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputRows))?;
        if output_rows > self.query.budget.output_rows() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::OutputRows,
            ));
        }
        let output_bytes = self
            .output_bytes
            .checked_add(bytes)
            .ok_or_else(|| QueryFailure::budget_exhausted(QueryBudgetDimension::OutputBytes))?;
        if output_bytes > self.query.budget.output_bytes() {
            return Err(QueryFailure::budget_exhausted(
                QueryBudgetDimension::OutputBytes,
            ));
        }
        Ok((output_rows, output_bytes))
    }
}
