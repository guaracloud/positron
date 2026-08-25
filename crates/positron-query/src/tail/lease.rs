use positron_kernel::{ActiveSegmentLedger, SnapshotLeaseId};

use crate::QueryFailure;

/// Owns one durable tail lease and retries failed release through the ledger's
/// existing pending-release authority.
pub(super) struct TailLeaseOwner<'ledger, 'kernel, 'catalog> {
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    identity: SnapshotLeaseId,
    released: bool,
}

impl<'ledger, 'kernel, 'catalog> TailLeaseOwner<'ledger, 'kernel, 'catalog> {
    pub(super) const fn new(
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
        identity: SnapshotLeaseId,
    ) -> Self {
        Self {
            ledger,
            identity,
            released: false,
        }
    }

    pub(super) fn release(&mut self) -> Result<(), QueryFailure> {
        if self.released {
            return Ok(());
        }
        self.ledger
            .release_snapshot_lease(self.identity)
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.released = true;
        Ok(())
    }
}

impl Drop for TailLeaseOwner<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.released {
            // `release_snapshot_lease` registers the identity in the ledger's
            // fixed-capacity pending-release set before publication. Ignoring
            // the returned error here is safe only because that durable intent
            // remains available for the ledger's deterministic retry path.
            let _ = self.ledger.release_snapshot_lease(self.identity);
        }
    }
}
