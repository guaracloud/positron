use super::super::cursor::{TailCursor, TailPosition};
use super::{AdvancedBatch, TailSession};
use crate::QueryFailure;

impl<'service, 'kernel, 'catalog, 'ledger> TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) fn candidate_advance(
        &self,
        positions: Vec<TailPosition>,
        digest: [u8; 32],
        output_rows: u64,
        output_bytes: u64,
        historical_complete: bool,
    ) -> Result<AdvancedBatch<'kernel, 'catalog, 'ledger>, QueryFailure> {
        let mut state = self.state.clone();
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
            state.clear_historical_markers();
        }
        let lease_rotation = self.prepare_lease_rotation(&mut state)?;
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
            state.clear_historical_markers();
        }
        let lease_rotation = self.prepare_lease_rotation(&mut state)?;
        let cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &state)?;
        self.commit_lease_rotation(lease_rotation)?;
        self.state = state;
        self.cursor = cursor;
        Ok(())
    }

    pub(in crate::tail) fn sync_progress(&mut self) -> Result<(), QueryFailure> {
        self.sync_state_progress();
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
}
