//! Direct encrypted active-segment append and authenticated durability frontiers.

mod append;
mod capacity;
mod fault;
mod format;
#[cfg(fuzzing)]
mod fuzzing;
mod io;
mod protection;
mod publication;
mod receipt;
mod recovery;
mod scope_discovery;
mod snapshot_lease;
mod snapshot_lease_codec;
mod snapshot_lease_pending;
mod snapshot_lease_record;
mod snapshot_lease_recovery;
mod state;
mod storage;
mod types;

#[cfg(test)]
mod tests;

use std::fmt::Formatter;
use std::sync::Mutex;

use positron_domain::routing::CommitPosition;

use crate::catalog::Catalog;
use crate::data_protection::ObjectDataKey;
use crate::resource_governor::{ActiveSegmentLeaseFailure, ActiveSegmentLedgerLease};
use crate::{
    RecoveryWorkClaim, RecoveryWorkKind, StorageKernelResourceAuthority, WorkClaim, WorkKind,
};

use capacity::{recovery_claim, retained_claim, snapshot_retained_claim};
use format::{SegmentMetadata, SegmentState};
use protection::{map_frame_failure, object_context};
use publication::{fresh_metadata, publish_segments};
pub use snapshot_lease::SnapshotLeaseGrant;
pub use snapshot_lease_record::{MAX_SNAPSHOT_LEASE_TTL_SECONDS, SnapshotLeaseId};
use state::{LedgerState, retain_recovered};
use storage::LedgerStorage;
pub use types::*;

const MAX_STORE_BLOCK_BYTES: usize = 1_048_576;
const MAX_RETAINED_BLOCKS: usize = 1_024;
const MAX_RETAINED_BLOCK_BYTES: usize = 1_048_576;
const MAX_ENCODED_FRAME_BYTES: u32 = 1_048_960;
const FORMAT_EPOCH: u32 = 1;

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_active_segment_stateful(data: &[u8]) {
    fuzzing::fuzz_active_segment_stateful(data);
}

/// The Storage Kernel-owned active segment for one physical tenant/signal/shard scope.
pub struct ActiveSegmentLedger<'kernel, 'catalog> {
    _writer: ActiveSegmentLedgerLease<'kernel>,
    authority: &'kernel StorageKernelResourceAuthority,
    catalog: &'catalog Catalog<'kernel>,
    scope: SegmentScope,
    storage: LedgerStorage,
    key: ObjectDataKey,
    state: Mutex<LedgerState<'kernel>>,
}

impl std::fmt::Debug for ActiveSegmentLedger<'_, '_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ActiveSegmentLedger { <storage-and-key-redacted> }")
    }
}

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Returns the Data Protection-owned bounded control-token operation.
    #[must_use]
    pub fn control_tokens(&self) -> crate::ControlTokenProtector<'_> {
        self.catalog.control_tokens()
    }

    pub fn open(
        authority: &'kernel StorageKernelResourceAuthority,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
    ) -> Result<Self, LedgerFailure> {
        Self::open_with_clock(
            authority,
            catalog,
            scope,
            protection,
            &crate::LifecycleClock::new(crate::lifecycle_clock::SystemLifecycleClockSource),
        )
    }

    pub fn open_with_clock<S: crate::LifecycleClockSource>(
        authority: &'kernel StorageKernelResourceAuthority,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        clock: &crate::LifecycleClock<S>,
    ) -> Result<Self, LedgerFailure> {
        let now = clock
            .assign_ingest_time()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?
            .instant()
            .value()
            .checked_div(1_000_000_000)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        Self::open_at(authority, catalog, scope, protection, now)
    }

    fn open_at(
        authority: &'kernel StorageKernelResourceAuthority,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        now: u64,
    ) -> Result<Self, LedgerFailure> {
        let writer = authority
            .acquire_active_segment_ledger(scope.lease_key())
            .map_err(|failure| match failure {
                ActiveSegmentLeaseFailure::Duplicate | ActiveSegmentLeaseFailure::Unavailable => {
                    LedgerFailure::new(LedgerFailureCode::ConcurrentWriter)
                },
                ActiveSegmentLeaseFailure::Capacity => {
                    LedgerFailure::new(LedgerFailureCode::LimitExceeded)
                },
            })?;
        let claim =
            RecoveryWorkClaim::tenant(scope.tenant, RecoveryWorkKind::Repair, recovery_claim())
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let _recovery = authority
            .recovery()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let base_claim = WorkClaim::tenant(scope.tenant, WorkKind::Ingest, retained_claim(0, 0)?)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservation = authority
            .governor()
            .reserve(base_claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        let mut storage = LedgerStorage::open(volume)?;
        let snapshot = catalog.pin()?;
        let recovered_leases = snapshot_lease_recovery::recover_reservations(
            authority, catalog, scope, &snapshot, now,
        )?;
        let snapshot = catalog.pin()?;
        let mut metadata = storage.catalog_segments(&snapshot, scope)?;
        let mut segments = metadata.iter().copied().peekable();
        let mut blocks = Vec::new();
        let mut retained_bytes = 0_usize;
        let mut frontier = CommitPosition::origin();
        let mut recovered_active = None;
        while let Some(first) = segments.peek().copied() {
            let base = first.base_position;
            if base != frontier {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            }

            let mut advancing_sealed = None;
            let mut active = None;
            while let Some(segment) = segments.next_if(|candidate| candidate.base_position == base)
            {
                let (key, recovered) =
                    storage.recover_segment(segment, &protection, catalog.instance())?;
                if segment.state == SegmentState::Active {
                    active = Some((segment, key, recovered));
                } else if recovered.frontier == base {
                    retain_recovered(recovered, &mut blocks, &mut retained_bytes, &mut frontier)?;
                } else if advancing_sealed
                    .replace((segment, key, recovered))
                    .is_some()
                {
                    return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                }
            }

            if advancing_sealed.is_some() && active.is_some() {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            }
            if let Some((_segment, _key, recovered)) = advancing_sealed {
                retain_recovered(recovered, &mut blocks, &mut retained_bytes, &mut frontier)?;
            }
            if let Some((segment, key, recovered)) = active {
                if segments.peek().is_some() {
                    return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
                }
                retain_recovered(recovered, &mut blocks, &mut retained_bytes, &mut frontier)?;
                recovered_active = Some((segment, key));
            }
        }

        let recovered_capacity = if blocks.is_empty() {
            None
        } else {
            let claim = WorkClaim::tenant(
                scope.tenant,
                WorkKind::Ingest,
                retained_claim(retained_bytes, blocks.len())?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            Some(
                authority
                    .governor()
                    .reserve(claim)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?,
            )
        };
        let successor = fresh_metadata(scope, frontier)?;
        let key = storage.create_active(successor, &protection, catalog.instance())?;
        if let Some((predecessor, _recovered_key)) = recovered_active {
            storage
                .seal(predecessor)
                .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
            metadata.retain(|candidate| candidate.id != predecessor.id);
            metadata.push(SegmentMetadata {
                state: SegmentState::Sealed,
                ..predecessor
            });
        }
        metadata.push(successor);
        publish_segments(catalog, &snapshot, &storage, scope, &metadata)
            .map_err(|failure| LedgerFailure::post_mutation(failure.code()))?;
        storage.set_current(successor);
        Ok(Self {
            _writer: writer,
            authority,
            catalog,
            scope,
            storage,
            key,
            state: Mutex::new(LedgerState {
                _capacity: reservation,
                retained_reservations: recovered_capacity.into_iter().collect(),
                frontier,
                blocks,
                retained_bytes,
                next_sequence: 0,
                poisoned: false,
                lease_reservations: recovered_leases.reservations,
                lease_resume_markers: recovered_leases.resume_markers,
                pending_lease_releases: snapshot_lease_pending::PendingLeaseReleases::new(),
                last_snapshot_lease_time: recovered_leases.last_observed,
            }),
        })
    }

    /// Builds an immutable snapshot for an already-admitted task. The caller's
    /// task reservation covers construction CPU; the returned snapshot retains
    /// only resources that remain live with the view.
    pub fn snapshot(&self) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let claim = WorkClaim::tenant(
            self.scope.tenant,
            WorkKind::InteractiveQueryTail,
            snapshot_retained_claim(state.retained_bytes, state.blocks.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let catalog = self.catalog.pin()?;
        Ok(LedgerSnapshot {
            _capacity: reservation,
            scope: self.scope,
            frontier: state.frontier,
            catalog_generation: catalog.number(),
            catalog_identity: catalog.identity(),
            blocks: state.blocks.clone(),
        })
    }

    /// Seals the current active segment without copying or re-encoding its bytes.
    pub fn seal(self) -> Result<SealedSegment, LedgerFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        if state.poisoned {
            return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
        }
        let current = self.storage.current_metadata()?;
        let basis = self.catalog.pin()?;
        let mut metadata = self.storage.catalog_segments(&basis, current.scope)?;
        self.storage.seal(current)?;
        let published = metadata
            .iter_mut()
            .find(|candidate| candidate.id == current.id)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        published.state = SegmentState::Sealed;
        publish_segments(
            self.catalog,
            &basis,
            &self.storage,
            current.scope,
            &metadata,
        )
        .map_err(|failure| LedgerFailure::ambiguous(failure.code()))?;
        Ok(SealedSegment {
            segment: current.id,
            frontier: state.frontier,
        })
    }
}
