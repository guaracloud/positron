use positron_kernel::SnapshotLeaseUsage;

use super::TailSession;
use crate::{QueryFailure, QueryFailureCode};

impl TailSession<'_, '_, '_, '_> {
    pub(super) fn persist_lease_usage(&mut self) -> Result<(), QueryFailure> {
        let (delivery_rows, delivery_bytes) = self
            .pending_batch
            .as_ref()
            .map_or((0, 0), |batch| (batch.rows, batch.bytes));
        let output_rows = self
            .output_rows
            .checked_add(delivery_rows)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let output_bytes = self
            .output_bytes
            .checked_add(delivery_bytes)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        let previous = self.lease_usage_before;
        let desired = SnapshotLeaseUsage::new(
            self.scanned_bytes.max(previous.scanned_bytes()),
            self.decoded_records.max(previous.decoded_records()),
            self.cpu_work_units.max(previous.cpu_work_units()),
            self.elapsed_seconds.max(previous.wall_seconds()),
            output_rows.max(previous.output_rows()),
            output_bytes.max(previous.output_bytes()),
            self.memory_peak_bytes.max(previous.memory_peak_bytes()),
        );
        let delta = SnapshotLeaseUsage::new(
            desired.scanned_bytes() - previous.scanned_bytes(),
            desired.decoded_records() - previous.decoded_records(),
            desired.cpu_work_units() - previous.cpu_work_units(),
            desired.wall_seconds() - previous.wall_seconds(),
            desired.output_rows() - previous.output_rows(),
            desired.output_bytes() - previous.output_bytes(),
            desired.memory_peak_bytes(),
        );
        let lease = self._lease.as_ref().ok_or_else(super::super::internal)?;
        let usage = match self.lease_attempt.as_ref() {
            Some(attempt) => self
                .service
                .ledger
                .record_snapshot_lease_usage_for_attempt(attempt, previous, delta),
            None => self
                .service
                .ledger
                .record_snapshot_lease_usage(lease.identity(), delta),
        }
        .map_err(crate::execution_support::map_ledger_failure)?;
        self.lease_usage_before = usage;
        self.lease_attempt = None;
        Ok(())
    }
}
