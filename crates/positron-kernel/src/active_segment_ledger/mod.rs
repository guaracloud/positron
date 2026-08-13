//! Direct encrypted active-segment append and authenticated durability frontiers.

mod capacity;
mod fault;
mod format;
#[cfg(fuzzing)]
mod fuzzing;
mod io;
mod protection;
mod publication;
mod recovery;
mod storage;
mod types;

#[cfg(test)]
mod tests;

use std::fmt::Formatter;
use std::sync::Mutex;

use positron_domain::routing::CommitPosition;

use crate::catalog::Catalog;
use crate::data_protection::{
    DataProtection, FrameLimits, FrameSequence, ObjectDataKey, SegmentFramePurpose,
};
use crate::resource_governor::{ActiveSegmentLeaseFailure, ActiveSegmentLedgerLease};
use crate::{
    RecoveryWorkClaim, RecoveryWorkKind, ResourceReservation, StorageKernelResourceAuthority,
    WorkClaim, WorkKind,
};

use capacity::{append_claim, recovery_claim, retained_claim, snapshot_claim};
use format::{SegmentMetadata, SegmentState};
use protection::{map_frame_failure, object_context};
use publication::{fresh_metadata, publish_segments};
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

struct LedgerState<'kernel> {
    _capacity: ResourceReservation<'kernel>,
    retained_reservations: Vec<ResourceReservation<'kernel>>,
    frontier: CommitPosition,
    blocks: Vec<CommittedBlock>,
    retained_bytes: usize,
    next_sequence: u64,
    poisoned: bool,
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
    pub fn open(
        authority: &'kernel StorageKernelResourceAuthority,
        catalog: &'catalog Catalog<'kernel>,
        scope: SegmentScope,
        protection: SegmentProtectionKey,
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
            }),
        })
    }

    pub fn append(&self, block: PreparedStoreBlock) -> Result<CommitReceipt, LedgerFailure> {
        self.append_inner(block, None)
    }

    /// Appends unless cancellation was requested before resource admission.
    ///
    /// Once admitted, the bounded durability operation runs to a typed terminal
    /// outcome so cancellation cannot strand a half-published frontier.
    pub fn append_cancellable(
        &self,
        block: PreparedStoreBlock,
        cancellation: &AppendCancellation,
    ) -> Result<CommitReceipt, LedgerFailure> {
        self.append_inner(block, Some(cancellation))
    }

    fn append_inner(
        &self,
        block: PreparedStoreBlock,
        cancellation: Option<&AppendCancellation>,
    ) -> Result<CommitReceipt, LedgerFailure> {
        if cancellation.is_some_and(AppendCancellation::is_cancelled) {
            return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
        }
        let amounts = append_claim(block.payload.len())?;
        let ordinary_claim = WorkClaim::tenant(self.scope.tenant, WorkKind::Ingest, amounts)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let _ordinary_work = self
            .authority
            .governor()
            .reserve(ordinary_claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let retained = WorkClaim::tenant(
            self.scope.tenant,
            WorkKind::Ingest,
            retained_claim(block.payload.len(), 1)?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let retained_reservation = self
            .authority
            .governor()
            .reserve(retained)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let claim = RecoveryWorkClaim::tenant(
            self.scope.tenant,
            RecoveryWorkKind::DurabilityCompletion,
            amounts,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let _reservation = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        if state.poisoned {
            return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
        }
        if let Some(committed) = state
            .blocks
            .iter()
            .find(|item| item.identity == block.identity)
        {
            if committed.payload != block.payload {
                return Err(LedgerFailure::new(LedgerFailureCode::IdempotencyConflict));
            }
            return Ok(receipt_for(committed));
        }
        let block_count = state
            .blocks
            .len()
            .checked_add(1)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let retained_bytes = state
            .retained_bytes
            .checked_add(block.payload.len())
            .filter(|bytes| {
                *bytes <= MAX_RETAINED_BLOCK_BYTES && block_count <= MAX_RETAINED_BLOCKS
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let position = state
            .frontier
            .next()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let context = self
            .key
            .object
            .frame(
                SegmentFramePurpose::StoreBlock,
                FrameSequence::new(
                    state
                        .next_sequence
                        .checked_add(1)
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                ),
            )
            .map_err(map_frame_failure)?;
        let limits = FrameLimits::new(MAX_ENCODED_FRAME_BYTES).map_err(map_frame_failure)?;
        let mut frame_plaintext = Vec::with_capacity(16 + block.payload.len());
        frame_plaintext.extend_from_slice(&block.identity.to_bytes());
        frame_plaintext.extend_from_slice(&block.payload);
        let encrypted = DataProtection::protect_frame(&self.key, context, &frame_plaintext, limits)
            .map_err(map_frame_failure)?;
        let authenticator = match self.storage.append_and_commit(
            &self.key,
            state.next_sequence,
            position,
            encrypted.as_bytes(),
        ) {
            Ok(authenticator) => authenticator,
            Err(failure) => {
                state.poisoned = true;
                return Err(failure);
            },
        };
        state.blocks.push(CommittedBlock {
            identity: block.identity,
            position,
            payload: block.payload,
            segment: self.storage.segment_id()?,
            frontier_authenticator: authenticator,
        });
        state.retained_reservations.push(retained_reservation);
        state.frontier = position;
        state.retained_bytes = retained_bytes;
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        Ok(CommitReceipt {
            segment: self.storage.segment_id()?,
            position,
            frontier_authenticator: authenticator,
        })
    }

    pub fn snapshot(&self) -> Result<LedgerSnapshot<'kernel>, LedgerFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let claim = WorkClaim::tenant(
            self.scope.tenant,
            WorkKind::InteractiveQueryTail,
            snapshot_claim(state.retained_bytes, state.blocks.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservation = self
            .authority
            .governor()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        Ok(LedgerSnapshot {
            _capacity: reservation,
            frontier: state.frontier,
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

fn receipt_for(block: &CommittedBlock) -> CommitReceipt {
    CommitReceipt {
        segment: block.segment,
        position: block.position,
        frontier_authenticator: block.frontier_authenticator,
    }
}

fn retain_recovered(
    recovered: recovery::RecoveryState,
    blocks: &mut Vec<CommittedBlock>,
    retained_bytes: &mut usize,
    frontier: &mut CommitPosition,
) -> Result<(), LedgerFailure> {
    let block_count = blocks
        .len()
        .checked_add(recovered.blocks.len())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let recovered_bytes = recovered
        .blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.payload.len())
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    *retained_bytes = retained_bytes
        .checked_add(recovered_bytes)
        .filter(|bytes| *bytes <= MAX_RETAINED_BLOCK_BYTES && block_count <= MAX_RETAINED_BLOCKS)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    *frontier = recovered.frontier;
    blocks.extend(recovered.blocks);
    Ok(())
}
