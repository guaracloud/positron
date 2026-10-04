use std::sync::Mutex;

use positron_kernel::{ActiveSegmentLedger, MaintenanceCoordinator, SnapshotLeaseId};

use crate::QueryFailure;

/// Owns one durable tail lease and retries failed release through the ledger's
/// existing pending-release authority.
pub(super) struct TailLeaseOwner<'ledger, 'kernel, 'catalog> {
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    identity: SnapshotLeaseId,
    maintenance: Option<&'ledger Mutex<MaintenanceCoordinator>>,
    released: bool,
    retained: bool,
}

pub(super) struct TailLeaseSet<'ledger, 'kernel, 'catalog> {
    owners: Vec<TailLeaseOwner<'ledger, 'kernel, 'catalog>>,
}

impl<'ledger, 'kernel, 'catalog> TailLeaseSet<'ledger, 'kernel, 'catalog> {
    pub(super) fn with_capacity(capacity: usize) -> Result<Self, QueryFailure> {
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(capacity)
            .map_err(|_| QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        Ok(Self { owners })
    }

    pub(super) fn push(&mut self, owner: TailLeaseOwner<'ledger, 'kernel, 'catalog>) {
        self.owners.push(owner);
    }

    pub(super) fn contains(&self, identity: SnapshotLeaseId) -> bool {
        self.owners.iter().any(|owner| owner.identity == identity)
    }

    pub(super) fn replace(
        &mut self,
        identity: SnapshotLeaseId,
        replacement: TailLeaseOwner<'ledger, 'kernel, 'catalog>,
    ) -> Result<TailLeaseOwner<'ledger, 'kernel, 'catalog>, QueryFailure> {
        let owner = self
            .owners
            .iter_mut()
            .find(|owner| owner.identity == identity)
            .ok_or_else(|| QueryFailure::new(crate::QueryFailureCode::InvalidCursor))?;
        Ok(std::mem::replace(owner, replacement))
    }

    pub(super) fn release(&mut self) -> Result<(), QueryFailure> {
        let mut first_failure = None;
        for owner in &mut self.owners {
            if let Err(failure) = owner.release() {
                crate::failure::retain_stronger(&mut first_failure, failure);
            }
        }
        first_failure.map_or(Ok(()), Err)
    }

    pub(super) fn retain(&mut self) {
        for owner in &mut self.owners {
            owner.retain();
        }
    }
}

impl<'ledger, 'kernel, 'catalog> TailLeaseOwner<'ledger, 'kernel, 'catalog> {
    pub(super) const fn new(
        ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
        identity: SnapshotLeaseId,
        maintenance: Option<&'ledger Mutex<MaintenanceCoordinator>>,
    ) -> Self {
        Self {
            ledger,
            identity,
            maintenance,
            released: false,
            retained: false,
        }
    }

    pub(super) fn release(&mut self) -> Result<(), QueryFailure> {
        if self.released || self.retained {
            return Ok(());
        }
        match self.maintenance {
            Some(maintenance) => {
                let coordinator = maintenance
                    .lock()
                    .map_err(|_| QueryFailure::new(crate::QueryFailureCode::Internal))?;
                self.ledger
                    .release_snapshot_lease_with_expiry_task(&coordinator, self.identity)
            },
            None => self.ledger.release_snapshot_lease(self.identity),
        }
        .map_err(crate::execution_support::map_ledger_failure)?;
        self.released = true;
        Ok(())
    }

    pub(super) fn retain(&mut self) {
        self.retained = true;
    }

    pub(super) const fn identity(&self) -> SnapshotLeaseId {
        self.identity
    }
}

impl Drop for TailLeaseOwner<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.released && !self.retained {
            // The kernel reserves MAX_SNAPSHOT_LEASES + 1 pending identities:
            // every admitted owner either already occupies one of those slots
            // or leaves a slot for this release. `release_snapshot_lease`
            // registers before publication, so Drop cannot lose the durable
            // intent; the kernel capacity proof covers the ignored result.
            if let Some(maintenance) = self.maintenance {
                if let Ok(coordinator) = maintenance.lock() {
                    let _ = self
                        .ledger
                        .release_snapshot_lease_with_expiry_task(&coordinator, self.identity);
                }
            } else {
                let _ = self.ledger.release_snapshot_lease(self.identity);
            }
        }
    }
}
