use positron_kernel::{
    ActiveSegmentLedger, ResourceReservation, SnapshotLeaseId, TransferredResourceReservation,
};

use crate::{QueryFailure, QueryFailureCode};

use crate::execution_support::map_ledger_failure;

/// Move-only ownership crossing the eager execution-to-stream boundary.
pub(crate) struct ExecutionResources {
    admission: TransferredResourceReservation,
    lease: SnapshotLeaseId,
}

impl ExecutionResources {
    pub(super) fn new(reservation: ResourceReservation<'_>, lease: SnapshotLeaseId) -> Self {
        Self {
            admission: reservation.transfer(),
            lease,
        }
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

    pub(super) fn into_stream(self) -> (TransferredResourceReservation, SnapshotLeaseId) {
        (self.admission, self.lease)
    }

    pub(super) fn invalid() -> QueryFailure {
        QueryFailure::new(QueryFailureCode::Internal)
    }
}
