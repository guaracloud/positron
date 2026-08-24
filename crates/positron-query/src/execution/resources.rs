use positron_kernel::{
    ActiveSegmentLedger, ResourceReservation, SnapshotLeaseId, SnapshotLeaseUsage,
    TransferredResourceReservation,
};

use crate::QueryFailure;

use crate::execution_support::map_ledger_failure;

/// Move-only ownership crossing the eager execution-to-stream boundary.
pub(crate) struct ExecutionResources {
    admission: TransferredResourceReservation,
    lease: SnapshotLeaseId,
    usage_before: SnapshotLeaseUsage,
}

impl ExecutionResources {
    pub(super) fn new(
        reservation: ResourceReservation<'_>,
        lease: SnapshotLeaseId,
        usage_before: SnapshotLeaseUsage,
    ) -> Self {
        Self {
            admission: reservation.transfer(),
            lease,
            usage_before,
        }
    }

    pub(super) fn persist_usage(
        &mut self,
        ledger: &ActiveSegmentLedger<'_, '_>,
        state: &crate::cursor::CursorState,
    ) -> Result<(), QueryFailure> {
        let previous = self.usage_before;
        let delta = SnapshotLeaseUsage::new(
            checked_delta(state.physical_scanned_bytes, previous.scanned_bytes())?,
            checked_delta(state.physical_decoded_records, previous.decoded_records())?,
            checked_delta(state.physical_cpu_work_units, previous.cpu_work_units())?,
            checked_delta(state.physical_elapsed_wall_seconds, previous.wall_seconds())?,
            checked_delta(state.physical_output_rows, previous.output_rows())?,
            checked_delta(state.physical_output_bytes, previous.output_bytes())?,
            state.physical_memory_peak_bytes,
        );
        self.usage_before = ledger
            .record_snapshot_lease_usage(self.lease, delta)
            .map_err(map_ledger_failure)?;
        Ok(())
    }

    pub(super) fn fail_before_stream(
        self,
        ledger: &ActiveSegmentLedger<'_, '_>,
        primary: QueryFailure,
    ) -> QueryFailure {
        let cleanup = ledger
            .release_snapshot_lease(self.lease)
            .map_err(map_ledger_failure);
        drop(self.admission);
        match cleanup {
            Ok(()) | Err(_) => primary,
        }
    }

    pub(super) fn fail_during_resume_planning(
        mut self,
        ledger: &ActiveSegmentLedger<'_, '_>,
        state: &crate::cursor::CursorState,
        primary: QueryFailure,
    ) -> QueryFailure {
        if let Err(failure) = self.persist_usage(ledger, state) {
            return failure;
        }
        drop(self.admission);
        primary
    }

    pub(super) fn validate_lease_identity(
        self,
        ledger: &ActiveSegmentLedger<'_, '_>,
        expected: [u8; 16],
    ) -> Result<Self, QueryFailure> {
        if self.lease.to_bytes() == expected {
            return Ok(self);
        }
        Err(self.fail_before_stream(ledger, QueryFailure::new(crate::QueryFailureCode::Internal)))
    }

    pub(super) fn into_stream(self) -> (TransferredResourceReservation, SnapshotLeaseId) {
        (self.admission, self.lease)
    }
}

fn checked_delta(current: u64, previous: u64) -> Result<u64, QueryFailure> {
    current
        .checked_sub(previous)
        .ok_or_else(|| QueryFailure::new(crate::QueryFailureCode::Internal))
}

#[cfg(test)]
mod tests;
