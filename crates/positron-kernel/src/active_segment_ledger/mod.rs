//! Direct encrypted active-segment append and authenticated durability frontiers.

mod fault;
mod format;
#[cfg(fuzzing)]
mod fuzzing;
mod io;
mod recovery;
mod storage;
mod types;

#[cfg(test)]
mod tests;

use std::fmt::Formatter;
use std::sync::Mutex;

use positron_domain::routing::CommitPosition;

use crate::catalog::{Catalog, CatalogObject, CatalogProposal, FormatEpoch, TransactionId};
use crate::data_protection::{
    DataProtection, FrameFormatEpoch, FrameLimits, FrameObjectContext, FrameObjectId,
    FrameSequence, KeyEpoch, ObjectDataKey, SegmentFramePurpose,
};
use crate::resource_governor::ActiveSegmentLedgerLease;
use crate::{
    RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceReservation,
    StorageKernelResourceAuthority,
};

use format::{SegmentMetadata, SegmentState};
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
            .acquire_active_segment_ledger()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        let claim =
            RecoveryWorkClaim::tenant(scope.tenant, RecoveryWorkKind::Repair, recovery_claim())
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let reservation = authority
            .recovery()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let volume = authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        let mut storage = LedgerStorage::open(volume)?;
        let snapshot = catalog.pin()?;
        let mut metadata = storage.catalog_segments(&snapshot, scope)?;
        let mut blocks = Vec::new();
        let mut retained_bytes = 0_usize;
        let mut frontier = CommitPosition::origin();
        let mut recovered_active = None;
        for segment in metadata.iter().copied() {
            if segment.base_position != frontier {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            }
            let (key, recovered) =
                storage.recover_segment(segment, &protection.0, catalog.instance())?;
            let block_count = blocks
                .len()
                .checked_add(recovered.blocks.len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            let recovered_bytes = recovered.blocks.iter().try_fold(0_usize, |total, block| {
                total.checked_add(block.payload.len())
            });
            retained_bytes = retained_bytes
                .checked_add(
                    recovered_bytes
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                )
                .filter(|bytes| {
                    *bytes <= MAX_RETAINED_BLOCK_BYTES && block_count <= MAX_RETAINED_BLOCKS
                })
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
            frontier = recovered.frontier;
            blocks.extend(recovered.blocks);
            if segment.state == SegmentState::Active {
                recovered_active = Some((segment, key));
            }
        }

        let successor = fresh_metadata(scope, frontier)?;
        let key = storage.create_active(successor, &protection.0, catalog.instance())?;
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
        publish_segments(catalog, &storage, scope, &metadata)
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
        let amounts = append_claim(block.0.len())?;
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
            .find(|committed| committed.payload == block.0)
        {
            return Ok(CommitReceipt {
                segment: committed.segment,
                position: committed.position,
                frontier_authenticator: committed.frontier_authenticator,
            });
        }
        let block_count = state
            .blocks
            .len()
            .checked_add(1)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let retained_bytes = state
            .retained_bytes
            .checked_add(block.0.len())
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
                FrameSequence::new(state.next_sequence),
            )
            .map_err(map_frame_failure)?;
        let limits = FrameLimits::new(MAX_ENCODED_FRAME_BYTES).map_err(map_frame_failure)?;
        let encrypted = DataProtection::protect_frame(&self.key, context, &block.0, limits)
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
            position,
            payload: block.0,
            segment: self.storage.segment_id()?,
            frontier_authenticator: authenticator,
        });
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

    pub fn snapshot(&self) -> Result<LedgerSnapshot, LedgerFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        Ok(LedgerSnapshot {
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
        let current = self.storage.current_metadata()?;
        self.storage.seal(current)?;
        let mut metadata = self
            .storage
            .catalog_segments(&self.catalog.pin()?, current.scope)?;
        let published = metadata
            .iter_mut()
            .find(|candidate| candidate.id == current.id)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::IntegrityCorruption))?;
        published.state = SegmentState::Sealed;
        publish_segments(self.catalog, &self.storage, current.scope, &metadata)
            .map_err(|failure| LedgerFailure::ambiguous(failure.code()))?;
        Ok(SealedSegment {
            segment: current.id,
            frontier: state.frontier,
        })
    }
}

fn fresh_metadata(
    scope: SegmentScope,
    base_position: CommitPosition,
) -> Result<SegmentMetadata, LedgerFailure> {
    let random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(
        random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    Ok(SegmentMetadata {
        scope,
        id: SegmentId::new(bytes)?,
        state: SegmentState::Active,
        base_position,
    })
}

fn publish_segments(
    catalog: &Catalog<'_>,
    storage: &LedgerStorage,
    scope: SegmentScope,
    metadata: &[SegmentMetadata],
) -> Result<(), LedgerFailure> {
    let mut objects = catalog.proposal_objects(|bytes| !storage.is_scope_metadata(bytes, scope))?;
    for segment in metadata {
        objects.push(CatalogObject::new(storage.metadata_object(*segment))?);
    }
    let transaction_random = DataProtection::random_identifier().map_err(map_frame_failure)?;
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(
        transaction_random
            .get(..16)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?,
    );
    let _commit = catalog.commit(
        catalog.pin()?.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::new(FORMAT_EPOCH)?,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn object_context(scope: SegmentScope, id: SegmentId) -> Result<FrameObjectContext, LedgerFailure> {
    Ok(FrameObjectContext::tenant_segment(
        scope.tenant,
        scope.signal,
        scope.shard,
        FrameObjectId::new(id.0).map_err(map_frame_failure)?,
        KeyEpoch::new(1),
        FrameFormatEpoch::new(FORMAT_EPOCH).map_err(map_frame_failure)?,
    ))
}

fn map_frame_failure(failure: crate::data_protection::FrameFailure) -> LedgerFailure {
    use crate::data_protection::FrameFailureCode as Code;
    let code = match failure.code() {
        Code::InvalidContext | Code::InvalidLimit => LedgerFailureCode::InvalidInput,
        Code::LimitExceeded => LedgerFailureCode::LimitExceeded,
        Code::SealFailed | Code::HashFailed | Code::EntropyUnavailable => {
            LedgerFailureCode::StorageUnavailable
        },
        Code::OpenFailed | Code::AuthenticationFailed => LedgerFailureCode::AuthenticationFailed,
        Code::MalformedFrame | Code::ChecksumMismatch => LedgerFailureCode::IntegrityCorruption,
        Code::UnsupportedVersion | Code::UnsupportedAlgorithm => {
            LedgerFailureCode::UnsupportedFormat
        },
    };
    LedgerFailure::new(code)
}

fn recovery_claim() -> ResourceAmounts {
    ResourceAmounts::new([2_500_000, 1, 1, 2_500_000, 1_024, 0, 1, 1, 1, 6, 0])
}
fn append_claim(block_bytes: usize) -> Result<ResourceAmounts, LedgerFailure> {
    let bytes = u64::try_from(block_bytes)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let frame = bytes
        .checked_add(384)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    Ok(ResourceAmounts::new([
        frame, 1, 1, frame, 1, 0, 1, 1, 1, 4, frame,
    ]))
}
