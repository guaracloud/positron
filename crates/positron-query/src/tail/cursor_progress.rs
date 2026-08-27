use super::{TailCursorState, TailPosition, invalid, resource};

impl TailCursorState {
    pub(crate) fn advance_batch(
        &self,
        updates: &[TailPosition],
        digest: [u8; 32],
    ) -> Result<Self, crate::QueryFailure> {
        if updates.is_empty() {
            return Err(invalid());
        }
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(self.positions.len())
            .map_err(|_| resource())?;
        positions.extend_from_slice(&self.positions);
        for update in updates {
            let entry = positions
                .iter_mut()
                .find(|entry| entry.shard == update.shard)
                .ok_or_else(|| crate::QueryFailure::new(crate::QueryFailureCode::InvalidCursor))?;
            if (update.position, update.ordinal) < (entry.position, entry.ordinal) {
                return Err(invalid());
            }
            entry.position = update.position;
            entry.ordinal = update.ordinal;
        }
        let sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
        let mut state = Self::new(
            self.principal,
            self.tenant,
            self.authorization_generation,
            self.plan_digest,
            self.signal_digest,
            positions,
            self.expiry,
            sequence,
            digest,
        )?;
        state.record_bound = true;
        state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            self.output_rows,
            self.output_bytes,
            self.cpu_work_units,
        );
        state.budget_digest = self.budget_digest;
        state.set_resume_stats(self.resume_count, self.repeated_batch_count);
        state.historical_markers = self.historical_markers.clone();
        state.snapshot_identity = self.snapshot_identity;
        state.snapshot_generation = self.snapshot_generation;
        state.source_bindings = self.source_bindings.clone();
        state.set_runtime_stats(
            self.memory_peak_bytes,
            self.elapsed_seconds,
            self.reduced_pruning,
            self.limiting_budget,
        );
        Ok(state)
    }

    pub(crate) fn advance_positions(
        &self,
        updates: &[TailPosition],
    ) -> Result<Self, crate::QueryFailure> {
        if updates.is_empty() {
            return Err(invalid());
        }
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(self.positions.len())
            .map_err(|_| resource())?;
        positions.extend_from_slice(&self.positions);
        for update in updates {
            let entry = positions
                .iter_mut()
                .find(|entry| entry.shard == update.shard)
                .ok_or_else(|| crate::QueryFailure::new(crate::QueryFailureCode::InvalidCursor))?;
            if (update.position, update.ordinal) < (entry.position, entry.ordinal) {
                return Err(invalid());
            }
            entry.position = update.position;
            entry.ordinal = update.ordinal;
        }
        let mut state = Self::new(
            self.principal,
            self.tenant,
            self.authorization_generation,
            self.plan_digest,
            self.signal_digest,
            positions,
            self.expiry,
            self.sequence,
            self.prior_digest,
        )?;
        state.record_bound = true;
        state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            self.output_rows,
            self.output_bytes,
            self.cpu_work_units,
        );
        state.budget_digest = self.budget_digest;
        state.set_resume_stats(self.resume_count, self.repeated_batch_count);
        state.historical_markers = self.historical_markers.clone();
        state.snapshot_identity = self.snapshot_identity;
        state.snapshot_generation = self.snapshot_generation;
        state.source_bindings = self.source_bindings.clone();
        state.set_runtime_stats(
            self.memory_peak_bytes,
            self.elapsed_seconds,
            self.reduced_pruning,
            self.limiting_budget,
        );
        Ok(state)
    }
}
