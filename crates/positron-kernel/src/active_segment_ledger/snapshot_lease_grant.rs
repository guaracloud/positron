use super::LedgerSnapshot;
use super::SnapshotLeaseAttempt;
use super::snapshot_lease_record::{SnapshotLeaseId, SnapshotLeaseUsage};

pub struct SnapshotLeaseGrant<'kernel> {
    pub(super) identity: SnapshotLeaseId,
    pub(super) expiry: u64,
    pub(super) resume_count: u64,
    pub(super) repeated_batch_count: u64,
    pub(super) usage: SnapshotLeaseUsage,
    pub(super) snapshot: LedgerSnapshot<'kernel>,
    pub(super) attempt: Option<SnapshotLeaseAttempt>,
}

impl std::fmt::Debug for SnapshotLeaseGrant<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotLeaseGrant")
            .field("identity", &self.identity)
            .field("expiry", &self.expiry)
            .field("snapshot", &"<pinned>")
            .finish()
    }
}

impl<'kernel> SnapshotLeaseGrant<'kernel> {
    #[must_use]
    pub const fn identity(&self) -> SnapshotLeaseId {
        self.identity
    }

    #[must_use]
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }

    #[must_use]
    pub const fn resume_count(&self) -> u64 {
        self.resume_count
    }

    #[must_use]
    pub const fn repeated_batch_count(&self) -> u64 {
        self.repeated_batch_count
    }

    #[must_use]
    pub const fn usage(&self) -> SnapshotLeaseUsage {
        self.usage
    }

    #[must_use]
    pub const fn snapshot(&self) -> &LedgerSnapshot<'kernel> {
        &self.snapshot
    }

    pub fn take_attempt(&mut self) -> Option<SnapshotLeaseAttempt> {
        self.attempt.take()
    }

    #[must_use]
    pub fn into_snapshot(self) -> LedgerSnapshot<'kernel> {
        self.snapshot
    }
}
