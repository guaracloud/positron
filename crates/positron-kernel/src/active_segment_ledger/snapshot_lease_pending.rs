use std::collections::{BTreeMap, BTreeSet};

use super::snapshot_lease::MAX_SNAPSHOT_LEASES;
use super::snapshot_lease_record::SnapshotLeaseId;
use super::{LedgerCompletionState, LedgerFailure, LedgerFailureCode};

// A create may publish one new lease while pruning the maximum number of
// expired leases. Keep that one bounded extra cleanup identity explicit rather
// than silently relying on the active-lease ceiling.
const MAX_PENDING_LEASE_RELEASES: usize = MAX_SNAPSHOT_LEASES + 1;

/// Fixed-capacity cleanup intent owned by the ledger that owns snapshot leases.
///
/// A release is registered before fallible catalog publication. The capacity
/// covers every active identity plus the one new identity that a create can
/// publish alongside a full expired set, so retries remain nonallocating.
pub(super) struct PendingLeaseReleases {
    identities: [Option<SnapshotLeaseId>; MAX_PENDING_LEASE_RELEASES],
}

impl PendingLeaseReleases {
    pub(super) const fn new() -> Self {
        Self {
            identities: [None; MAX_PENDING_LEASE_RELEASES],
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

    pub(super) fn remove(&mut self, identity: SnapshotLeaseId) {
        if let Some(slot) = self
            .identities
            .iter_mut()
            .find(|slot| slot.is_some_and(|held| held == identity))
        {
            *slot = None;
        }
    }
}

pub(super) fn register_all(
    pending: &mut PendingLeaseReleases,
    identities: impl IntoIterator<Item = SnapshotLeaseId>,
) -> Result<(), LedgerFailure> {
    for identity in identities {
        pending.register(identity)?;
    }
    Ok(())
}

pub(super) fn remove_all(
    pending: &mut PendingLeaseReleases,
    identities: impl IntoIterator<Item = SnapshotLeaseId>,
) {
    for identity in identities {
        pending.remove(identity);
    }
}

pub(super) fn register_lease_reservation<V>(
    reservations: &mut BTreeMap<SnapshotLeaseId, V>,
    pending: &mut PendingLeaseReleases,
    identity: SnapshotLeaseId,
    value: V,
    expired: &BTreeSet<SnapshotLeaseId>,
) -> Result<(), LedgerFailure> {
    register_all(pending, expired.iter().copied())?;
    pending.register(identity)?;
    if reservations.insert(identity, value).is_some() {
        reservations.remove(&identity);
        pending.remove(identity);
        remove_all(pending, expired.iter().copied());
        return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
    }
    Ok(())
}

pub(super) fn cleanup_expired_on_resume_failure(
    pending: &mut PendingLeaseReleases,
    expired: &BTreeSet<SnapshotLeaseId>,
    failure: LedgerFailure,
) -> LedgerFailure {
    if failure.completion_state() != LedgerCompletionState::CommitAmbiguous {
        remove_all(pending, expired.iter().copied());
    }
    failure
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        PendingLeaseReleases, cleanup_expired_on_resume_failure, register_lease_reservation,
    };
    use crate::{LedgerFailure, LedgerFailureCode, SnapshotLeaseId};

    #[test]
    fn duplicate_lease_reservation_is_cleaned_up_fail_closed() {
        let identity = SnapshotLeaseId::new([7; 16]).expect("nonzero identity");
        let mut reservations = BTreeMap::from([(identity, ())]);
        let mut pending = PendingLeaseReleases::new();

        let expired = BTreeSet::from([SnapshotLeaseId::new([8; 16]).expect("nonzero identity")]);
        let failure =
            register_lease_reservation(&mut reservations, &mut pending, identity, (), &expired)
                .expect_err("duplicate identity must be an integrity failure");

        assert_eq!(failure.code(), LedgerFailureCode::IntegrityCorruption);
        assert!(reservations.is_empty());
        assert_eq!(pending.identities().count(), 0);
    }

    #[test]
    fn definitive_resume_failure_clears_expiry_cleanup_intent() {
        let identity = SnapshotLeaseId::new([7; 16]).expect("nonzero identity");
        let expired = BTreeSet::from([identity]);
        let mut pending = PendingLeaseReleases::new();
        pending.register(identity).expect("pending capacity");

        let failure = cleanup_expired_on_resume_failure(
            &mut pending,
            &expired,
            LedgerFailure::new(LedgerFailureCode::StaleGeneration),
        );

        assert_eq!(failure.code(), LedgerFailureCode::StaleGeneration);
        assert_eq!(pending.identities().count(), 0);
    }
}
