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
mod reader;
mod receipt;
mod reconstruction;
mod recovery;
mod retention;
mod retention_frontier;
mod scope_discovery;
mod snapshot_lease;
mod snapshot_lease_attempt;
mod snapshot_lease_codec;
mod snapshot_lease_grant;
mod snapshot_lease_pending;
mod snapshot_lease_record;
mod snapshot_lease_recovery;
mod snapshot_lease_replace;
mod snapshot_lease_usage;
mod snapshot_protection;
mod state;
mod storage;
#[cfg(feature = "test-support")]
mod test_support;
mod types;

#[cfg(test)]
mod tests;

use std::fmt::Formatter;
use std::sync::{Arc, Mutex};

use crate::catalog::Catalog;
use crate::data_protection::ObjectDataKey;
use crate::resource_governor::{ActiveSegmentLeaseFailure, ActiveSegmentLedgerLease};
use crate::{
    CatalogSnapshot, RecoveryWorkClaim, RecoveryWorkKind, ResourceReservation,
    StorageKernelResourceAuthority, WorkClaim, WorkKind,
};

use capacity::{recovery_claim, retained_claim, snapshot_retained_claim};
use format::{SegmentMetadata, SegmentState};
use protection::{map_frame_failure, object_context};
use publication::{fresh_metadata, publish_segments};
pub use reader::CommittedLedgerReader;
use reconstruction::reconstruct;
pub use snapshot_lease_attempt::SnapshotLeaseAttempt;
pub use snapshot_lease_grant::SnapshotLeaseGrant;
pub use snapshot_lease_record::{
    MAX_SNAPSHOT_LEASE_TTL_SECONDS, SnapshotLeaseId, SnapshotLeaseUsage,
};
pub use snapshot_lease_replace::SnapshotLeaseReplacement;
use snapshot_protection::SnapshotProtection;
use state::LedgerState;
use storage::LedgerStorage;
#[cfg(feature = "test-support")]
pub use test_support::publish_snapshot_lease_marker_for_test;
pub use types::*;

/// Result of a kernel-owned whole-segment retention publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionReclamation {
    logically_retired_segments: usize,
    physically_reclaimed_segments: usize,
    evaluated_at: positron_domain::time::UnixNanoseconds,
}

impl RetentionReclamation {
    #[must_use]
    pub const fn logically_retired_segments(self) -> usize {
        self.logically_retired_segments
    }

    #[must_use]
    pub const fn physically_reclaimed_segments(self) -> usize {
        self.physically_reclaimed_segments
    }

    #[must_use]
    pub const fn evaluated_at(self) -> positron_domain::time::UnixNanoseconds {
        self.evaluated_at
    }
}

/// Move-only, pre-admitted retention evaluation over one authenticated ledger state.
pub struct RetentionEvaluation<'ledger, 'kernel, 'catalog> {
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    _capacity: ResourceReservation<'kernel>,
    catalog_identity: crate::CatalogGenerationId,
    frontier: crate::IngestTime,
    cutoff: positron_domain::time::UnixNanoseconds,
    blocks: Vec<CommittedBlock>,
}

impl<'ledger, 'kernel, 'catalog> RetentionEvaluation<'ledger, 'kernel, 'catalog> {
    #[must_use]
    pub fn blocks(&self) -> &[CommittedBlock] {
        &self.blocks
    }

    pub fn commit(self) -> Result<RetentionReclamation, LedgerFailure> {
        retention::commit(self)
    }
}

fn map_retention_time_failure(failure: crate::LifecycleClockFailure) -> LedgerFailure {
    let code = match failure {
        crate::LifecycleClockFailure::Unavailable => LedgerFailureCode::StorageUnavailable,
        crate::LifecycleClockFailure::OutOfRange => LedgerFailureCode::LimitExceeded,
    };
    LedgerFailure::new(code)
}

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

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_snapshot_lease_record(data: &[u8]) {
    snapshot_lease_codec::fuzz_snapshot_lease_record(data);
}

/// The Storage Kernel-owned active segment for one physical tenant/signal/shard scope.
pub struct ActiveSegmentLedger<'kernel, 'catalog> {
    _writer: ActiveSegmentLedgerLease<'kernel>,
    authority: &'kernel StorageKernelResourceAuthority,
    retention_time: Option<&'kernel crate::RetentionTimeAuthority>,
    catalog: &'catalog Catalog<'kernel>,
    scope: SegmentScope,
    storage: LedgerStorage,
    protection: SegmentProtectionKey,
    key: ObjectDataKey,
    state: Mutex<LedgerState<'kernel>>,
    lease_attempts: Arc<Mutex<snapshot_lease_attempt::LeaseAttemptRegistry>>,
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

    /// Refreshes and pins the latest authenticated Catalog generation.
    ///
    /// Query authorization is generation-pinned, so callers must use this
    /// boundary immediately before admitting a durable snapshot lease rather
    /// than relying on an identity captured during planning.
    pub fn current_catalog_snapshot(&self) -> Result<CatalogSnapshot, LedgerFailure> {
        self.catalog.refresh_state()?;
        self.catalog.pin().map_err(Into::into)
    }

    /// Returns the monotonic timestamp persisted by Snapshot Lease recovery.
    ///
    /// Query runtimes may use a clock source that lags the lifecycle clock used
    /// while reopening a ledger. Lease operations must still be attempted at
    /// this floor so a valid durable lease is not mistaken for a clock
    /// regression during reconnect.
    pub fn snapshot_lease_time(&self) -> Result<u64, LedgerFailure> {
        self.state
            .lock()
            .map(|state| state.last_snapshot_lease_time)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))
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

    pub fn open_with_retention_time(
        authority: &'kernel StorageKernelResourceAuthority,
        retention_time: &'kernel crate::RetentionTimeAuthority,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
    ) -> Result<Self, LedgerFailure> {
        Self::open_at(
            authority,
            Some(retention_time),
            catalog,
            scope,
            protection,
            None,
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
        Self::open_at(authority, None, catalog, scope, protection, Some(now))
    }

    fn open_at(
        authority: &'kernel StorageKernelResourceAuthority,
        retention_time: Option<&'kernel crate::RetentionTimeAuthority>,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
        lifecycle_now: Option<u64>,
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
        let mut retained_capacity = authority
            .governor()
            .reserve(base_claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        let mut storage = LedgerStorage::open(volume)?;
        let snapshot = catalog.pin()?;
        let retention_frontier = retention_frontier::recover(&snapshot, scope)?;
        let lease_recovery_time = match retention_time {
            Some(authority) => authority
                .lease_recovery_time(scope, retention_frontier)
                .map_err(map_retention_time_failure)?,
            None => lifecycle_now,
        };
        let recovered_leases = snapshot_lease_recovery::recover_reservations(
            authority,
            catalog,
            scope,
            &snapshot,
            lease_recovery_time,
        )?;
        let snapshot = catalog.pin()?;
        let mut metadata = storage.catalog_segments(&snapshot, scope)?;
        let reconstruction = reconstruct(
            &storage,
            &metadata,
            &protection,
            catalog.instance(),
            recovery::RecoveryMode::Repair,
        )?;
        let blocks = reconstruction.blocks;
        let retained_bytes = reconstruction.retained_bytes;
        let frontier = reconstruction.frontier;
        let recovered_active = reconstruction.recovered_active;

        retained_capacity
            .try_resize_preserving_capacity(retained_claim(retained_bytes, blocks.len())?)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
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
            retention_time,
            catalog,
            scope,
            storage,
            protection,
            key,
            state: Mutex::new(LedgerState {
                retained_capacity,
                frontier,
                blocks,
                retained_bytes,
                next_sequence: 0,
                poisoned: false,
                lease_reservations: recovered_leases.reservations,
                lease_reservation_baselines: std::collections::BTreeMap::new(),
                lease_resume_markers: recovered_leases.resume_markers,
                pending_lease_releases: snapshot_lease_pending::PendingLeaseReleases::new(),
                last_snapshot_lease_time: recovered_leases.last_observed,
                retention_frontier,
            }),
            lease_attempts: Arc::new(Mutex::new(
                snapshot_lease_attempt::LeaseAttemptRegistry::new(),
            )),
        })
    }

    /// Opens a read-only observation handle without acquiring another writer
    /// lease. The reader shares the immutable protection capability only.
    pub fn reader<'ledger>(
        &'ledger self,
    ) -> Result<CommittedLedgerReader<'kernel, 'catalog, 'ledger>, LedgerFailure> {
        CommittedLedgerReader::open_with_lease_authority(self)
    }

    #[must_use]
    pub const fn scope(&self) -> SegmentScope {
        self.scope
    }

    /// Mints the authoritative Ingest Time for one Signal Store preparation.
    pub fn begin_store_block<'capacity>(
        &self,
        capacity: ResourceReservation<'capacity>,
        identity: StoreBlockIdentity,
    ) -> Result<StoreBlockPreparation<'capacity>, LedgerFailure> {
        if !capacity.belongs_to(self.authority.governor())
            || !capacity.authorizes_ingest_preparation(self.scope.tenant, 1_048_576)
        {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let retention_time = self
            .retention_time
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let ingest_time = retention_time
            .ingest_time(self.scope, state.retention_frontier)
            .map_err(map_retention_time_failure)?;
        if state.retention_frontier.is_none() {
            self.catalog.refresh_state()?;
            let basis = self.catalog.pin()?;
            retention_frontier::publish(self.catalog, &basis, self.scope, ingest_time)?;
            state.retention_frontier = Some(ingest_time);
        }
        Ok(StoreBlockPreparation {
            scope: self.scope,
            identity,
            ingest_time,
            retention_ingest_time: Some(ingest_time),
            capacity,
        })
    }

    /// Mints deterministic, retention-ineligible Ingest Time for cross-crate tests.
    #[cfg(feature = "test-support")]
    pub fn begin_store_block_for_test<'capacity>(
        &self,
        capacity: ResourceReservation<'capacity>,
        identity: StoreBlockIdentity,
        retention_time: &crate::RetentionTimeAuthority,
    ) -> Result<StoreBlockPreparation<'capacity>, LedgerFailure> {
        if !capacity.belongs_to(self.authority.governor())
            || !capacity.authorizes_ingest_preparation(self.scope.tenant, 1_048_576)
        {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        if retention_time.authorizes_destructive_retention() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        let ingest_time = retention_time
            .ingest_time(self.scope, None)
            .map_err(map_retention_time_failure)?;
        Ok(StoreBlockPreparation {
            scope: self.scope,
            identity,
            ingest_time,
            retention_ingest_time: None,
            capacity,
        })
    }

    /// Returns the active segment identity for this physical scope.
    pub fn active_segment_id(&self) -> Result<SegmentId, LedgerFailure> {
        self.storage.segment_id()
    }

    /// Admits one retention pass without accepting caller-selected time or segments.
    pub fn begin_retention<'ledger>(
        &'ledger self,
        duration: std::num::NonZeroU64,
    ) -> Result<RetentionEvaluation<'ledger, 'kernel, 'catalog>, LedgerFailure> {
        let retention_time = self
            .retention_time
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::UnsupportedFormat))?;
        if !retention_time.authorizes_destructive_retention() {
            return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
        }
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let catalog_bytes = basis
            .plaintext_objects()
            .try_fold(0_usize, |total, bytes| {
                total
                    .checked_add(bytes.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
            })?;
        let inspected_bytes = state
            .retained_bytes
            .checked_add(catalog_bytes)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let inspected_items = state
            .blocks
            .len()
            .checked_add(basis.plaintext_object_count())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let claim = RecoveryWorkClaim::tenant(
            self.scope.tenant,
            RecoveryWorkKind::Retention,
            capacity::retention_claim(inspected_bytes, inspected_items)?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let capacity = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let frontier = retention_time
            .ingest_time(self.scope, state.retention_frontier)
            .map_err(map_retention_time_failure)?;
        let duration_nanos = duration
            .get()
            .checked_mul(1_000_000_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let cutoff = frontier
            .instant()
            .value()
            .checked_sub(duration_nanos)
            .map(positron_domain::time::UnixNanoseconds::new)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let blocks = state.blocks.clone();
        Ok(RetentionEvaluation {
            ledger: self,
            _capacity: capacity,
            catalog_identity: basis.identity(),
            frontier,
            cutoff,
            blocks,
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
        let barrier = SnapshotProtection::read_barrier(self.authority.snapshot_barrier())?;
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
            _protection: SnapshotProtection::with_barrier(
                self.authority.snapshot_protection(),
                barrier,
                state.blocks.iter().map(CommittedBlock::segment_id),
            )?,
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
