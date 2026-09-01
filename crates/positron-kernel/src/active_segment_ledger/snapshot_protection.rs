use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{CommittedBlock, LedgerFailure, LedgerFailureCode, SegmentId};

type SnapshotProtectionRegistry = Arc<Mutex<BTreeMap<[u8; 16], usize>>>;

/// A non-owning physical protection claim held by one immutable snapshot.
///
/// The registry is shared by readers and the writer for one Storage Kernel.
/// Retention may remove a segment from future snapshots, but it must retain the
/// bytes while any already-created snapshot still references that segment.
pub(super) struct SnapshotProtection {
    registry: SnapshotProtectionRegistry,
    segments: Vec<[u8; 16]>,
}

impl SnapshotProtection {
    pub(super) fn for_blocks(
        registry: SnapshotProtectionRegistry,
        barrier: &RwLock<()>,
        blocks: &[CommittedBlock],
    ) -> Result<Self, LedgerFailure> {
        let barrier = barrier
            .read()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        Self::with_barrier(
            registry,
            barrier,
            blocks.iter().map(CommittedBlock::segment_id),
        )
    }

    pub(super) fn read_barrier<'kernel>(
        barrier: &'kernel RwLock<()>,
    ) -> Result<RwLockReadGuard<'kernel, ()>, LedgerFailure> {
        barrier
            .read()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
    }

    pub(super) fn write_barrier<'kernel>(
        barrier: &'kernel RwLock<()>,
    ) -> Result<RwLockWriteGuard<'kernel, ()>, LedgerFailure> {
        barrier
            .write()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
    }

    pub(super) fn with_barrier<'kernel>(
        registry: SnapshotProtectionRegistry,
        barrier: RwLockReadGuard<'kernel, ()>,
        segments: impl IntoIterator<Item = SegmentId>,
    ) -> Result<Self, LedgerFailure> {
        let mut identities = Vec::new();
        for segment in segments {
            let identity = segment.to_bytes();
            if !identities.contains(&identity) {
                identities
                    .try_reserve(1)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
                identities.push(identity);
            }
        }
        let mut counts = registry
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        for identity in &identities {
            let count = counts.entry(*identity).or_insert(0);
            *count = count
                .checked_add(1)
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        }
        drop(counts);
        drop(barrier);
        Ok(Self {
            registry,
            segments: identities,
        })
    }

    pub(super) fn is_protected(
        registry: &SnapshotProtectionRegistry,
        segment: SegmentId,
    ) -> Result<bool, LedgerFailure> {
        registry
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
            .map(|counts| {
                counts
                    .get(&segment.to_bytes())
                    .is_some_and(|count| *count != 0)
            })
    }
}

impl Drop for SnapshotProtection {
    fn drop(&mut self) {
        let Ok(mut counts) = self.registry.lock() else {
            return;
        };
        for identity in self.segments.drain(..) {
            match counts.get_mut(&identity) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    counts.remove(&identity);
                },
                None => {},
            }
        }
    }
}
