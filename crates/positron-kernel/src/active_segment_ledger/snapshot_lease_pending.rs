use super::snapshot_lease::{MAX_SNAPSHOT_LEASES, SnapshotLeaseId};
use super::{LedgerFailure, LedgerFailureCode};

/// Fixed-capacity cleanup intent owned by the ledger that owns snapshot leases.
///
/// A release is registered before fallible catalog publication. The capacity is
/// exactly the active lease ceiling, so every valid active identity always has a
/// nonallocating retry slot.
pub(super) struct PendingLeaseReleases {
    identities: [Option<SnapshotLeaseId>; MAX_SNAPSHOT_LEASES],
}

impl PendingLeaseReleases {
    pub(super) const fn new() -> Self {
        Self {
            identities: [None; MAX_SNAPSHOT_LEASES],
        }
    }

    pub(super) fn register(&mut self, identity: SnapshotLeaseId) -> Result<(), LedgerFailure> {
        if self
            .identities
            .iter()
            .flatten()
            .any(|held| *held == identity)
        {
            return Ok(());
        }
        let slot = self
            .identities
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        *slot = Some(identity);
        Ok(())
    }

    pub(super) fn identities(&self) -> impl Iterator<Item = SnapshotLeaseId> + '_ {
        self.identities.iter().flatten().copied()
    }

    pub(super) fn clear(&mut self) {
        self.identities.fill(None);
    }
}
