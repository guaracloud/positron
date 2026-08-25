//! Bounded in-process ownership for one eager marked lease attempt.
//!
//! Admission follows ledger state, registry, then Catalog. The guard retains
//! no lock while query work runs; dropping it takes only the registry lock.

use std::sync::{Arc, Mutex, TryLockError};

use super::snapshot_lease::MAX_SNAPSHOT_LEASES;
use super::{LedgerFailure, LedgerFailureCode, SnapshotLeaseId};

pub(super) struct LeaseAttemptRegistry {
    active: [Option<SnapshotLeaseId>; MAX_SNAPSHOT_LEASES],
}

impl LeaseAttemptRegistry {
    pub(super) const fn new() -> Self {
        Self {
            active: [None; MAX_SNAPSHOT_LEASES],
        }
    }
}

#[must_use = "a live lease attempt guard prevents concurrent resume work"]
pub struct SnapshotLeaseAttempt {
    registry: Arc<Mutex<LeaseAttemptRegistry>>,
    identity: SnapshotLeaseId,
    resume_count: u64,
}

impl SnapshotLeaseAttempt {
    pub(super) fn acquire(
        registry: &Arc<Mutex<LeaseAttemptRegistry>>,
        identity: SnapshotLeaseId,
        resume_count: u64,
    ) -> Result<Self, LedgerFailure> {
        let mut active = match registry.try_lock() {
            Ok(active) => active,
            Err(TryLockError::Poisoned(_)) | Err(TryLockError::WouldBlock) => {
                return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
            },
        };
        if active.active.contains(&Some(identity)) {
            return Err(LedgerFailure::new(LedgerFailureCode::ConcurrentWriter));
        }
        let slot = active
            .active
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        *slot = Some(identity);
        drop(active);
        Ok(Self {
            registry: Arc::clone(registry),
            identity,
            resume_count,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> SnapshotLeaseId {
        self.identity
    }

    #[must_use]
    pub const fn resume_count(&self) -> u64 {
        self.resume_count
    }

    pub(super) fn belongs_to(&self, registry: &Arc<Mutex<LeaseAttemptRegistry>>) -> bool {
        Arc::ptr_eq(&self.registry, registry)
    }

    pub(super) fn set_resume_count(&mut self, resume_count: u64) {
        self.resume_count = resume_count;
    }
}

impl LeaseAttemptRegistry {
    pub(super) fn contains(&self, identity: SnapshotLeaseId) -> bool {
        self.active.contains(&Some(identity))
    }
}

impl Drop for SnapshotLeaseAttempt {
    fn drop(&mut self) {
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(slot) = registry
            .active
            .iter_mut()
            .find(|entry| **entry == Some(self.identity))
        {
            *slot = None;
        }
    }
}
