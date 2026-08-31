use crate::data_protection::{DataProtection, FrameLimits, FrameSequence, SegmentFramePurpose};
use crate::{RecoveryWorkClaim, RecoveryWorkKind, WorkClaim, WorkKind};

use super::capacity::{append_claim, retained_claim};
use super::protection::map_frame_failure;
use super::state::receipt_for;
use super::storage;
use super::{
    ActiveSegmentLedger, AppendCancellation, CommitReceipt, CommittedBlock, LedgerFailure,
    LedgerFailureCode, MAX_ENCODED_FRAME_BYTES, MAX_RETAINED_BLOCK_BYTES, MAX_RETAINED_BLOCKS,
    PreparedStoreBlock,
};

impl<'kernel> ActiveSegmentLedger<'kernel, '_> {
    pub fn append(
        &self,
        block: PreparedStoreBlock<'kernel>,
    ) -> Result<CommitReceipt, LedgerFailure> {
        self.append_inner(block, None)
    }

    /// Appends unless cancellation was requested before resource admission.
    ///
    /// Once admitted, the bounded durability operation runs to a typed terminal
    /// outcome so cancellation cannot strand a half-published frontier.
    pub fn append_cancellable(
        &self,
        block: PreparedStoreBlock<'kernel>,
        cancellation: &AppendCancellation,
    ) -> Result<CommitReceipt, LedgerFailure> {
        self.append_inner(block, Some(cancellation))
    }

    fn append_inner(
        &self,
        mut block: PreparedStoreBlock<'kernel>,
        cancellation: Option<&AppendCancellation>,
    ) -> Result<CommitReceipt, LedgerFailure> {
        if block.scope != self.scope {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        if self.retention_time.is_some() && block.retention_ingest_time.is_none() {
            return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
        }
        if block.preparation_capacity.as_ref().is_some_and(|capacity| {
            !capacity.belongs_to(self.authority.governor())
                || !capacity.authorizes_ingest_preparation(
                    self.scope.tenant,
                    u64::try_from(block.payload.len()).unwrap_or(u64::MAX),
                )
        }) {
            return Err(LedgerFailure::new(
                LedgerFailureCode::ResourceAdmissionRefused,
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
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
        if cancellation.is_some_and(AppendCancellation::is_cancelled) {
            return Err(LedgerFailure::new(LedgerFailureCode::Cancelled));
        }
        if state.poisoned {
            return Err(LedgerFailure::new(LedgerFailureCode::RecoveryRequired));
        }
        let amounts = append_claim(block.payload.len())?;
        let ordinary_claim = WorkClaim::tenant(self.scope.tenant, WorkKind::Ingest, amounts)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let mut ordinary_work = if let Some(capacity) = block.preparation_capacity.take() {
            capacity
        } else {
            self.authority
                .governor()
                .reserve(ordinary_claim)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?
        };
        if ordinary_work.granted() != amounts {
            ordinary_work
                .try_resize(amounts)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        }
        let claim = RecoveryWorkClaim::tenant(
            self.scope.tenant,
            RecoveryWorkKind::DurabilityCompletion,
            amounts,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
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
        let segment = self.storage.segment_id()?;
        let prior_retention = state
            .blocks
            .iter()
            .filter(|committed| committed.segment == segment)
            .fold(super::SegmentRetention::Empty, |aggregate, committed| {
                aggregate.append_block(committed.block_retention)
            });
        let block_retention = super::SegmentRetention::for_block(block.retention_ingest_time);
        let segment_retention = prior_retention.append_block(block_retention);
        let content_digest = block.content_digest()?;
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
        let mut frame_plaintext = Vec::with_capacity(25 + block.payload.len());
        frame_plaintext.extend_from_slice(&block.identity.to_bytes());
        let (retention_tag, retention_instant) = match block_retention {
            super::SegmentRetention::Complete(instant) => (2_u8, instant.instant().value()),
            super::SegmentRetention::Unavailable => (1_u8, 0_i64),
            super::SegmentRetention::Empty => {
                return Err(LedgerFailure::new(LedgerFailureCode::IntegrityCorruption));
            },
        };
        frame_plaintext.push(retention_tag);
        frame_plaintext.extend_from_slice(&retention_instant.to_be_bytes());
        frame_plaintext.extend_from_slice(&block.payload);
        let frame_bytes = DataProtection::protected_frame_length(frame_plaintext.len(), limits)
            .map_err(map_frame_failure)?;
        let previous_retained = state.retained_capacity.granted();
        state
            .retained_capacity
            .try_resize_preserving_capacity(retained_claim(retained_bytes, block_count)?)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let authenticator = match self.storage.append_and_commit(
            &self.key,
            storage::NextFrontier {
                sequence: state.next_sequence,
                position,
                segment_retention,
            },
            frame_bytes,
            || {
                DataProtection::protect_frame(&self.key, context, &frame_plaintext, limits)
                    .map_err(map_frame_failure)
            },
            || {
                self.authority
                    .recovery()
                    .reserve(claim)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))
            },
        ) {
            Ok(authenticator) => authenticator,
            Err(storage::AppendFailure::RejectedBeforeMutation(failure)) => {
                state
                    .retained_capacity
                    .try_resize_preserving_capacity(previous_retained)
                    .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
                return Err(failure);
            },
            Err(storage::AppendFailure::SegmentMutated(failure)) => {
                state.poisoned = true;
                return Err(failure);
            },
        };
        state.blocks.push(CommittedBlock {
            identity: block.identity,
            position,
            payload: block.payload,
            content_digest,
            segment,
            frontier_authenticator: authenticator,
            block_retention,
        });
        state.frontier = position;
        state.retained_bytes = retained_bytes;
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        Ok(CommitReceipt {
            segment,
            position,
            frontier_authenticator: authenticator,
        })
    }
}
