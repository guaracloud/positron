use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use crate::RecoveryWorkKind;
use crate::data_protection::{DataProtection, FrameLimits, FrameSequence, SegmentFramePurpose};

use super::format::{SegmentMetadata, SegmentState};
use super::publication::{fresh_metadata, publish_segments};
use super::storage::{AppendFailure, LedgerStorage, NextFrontier};
use super::{
    ActiveSegmentLedger, CommittedBlock, CompactionBlock, CompactionPublication, LedgerFailure,
    LedgerFailureCode, RecoveryWorkClaim, SegmentRetention,
};

const MAX_COMPACTION_BLOCKS: usize = 1_024;
const MAX_ENCODED_FRAME_BYTES: u32 = super::MAX_ENCODED_FRAME_BYTES;

impl<'kernel, 'catalog> ActiveSegmentLedger<'kernel, 'catalog> {
    /// Atomically replaces the supplied sealed blocks with copy-on-write
    /// sealed segments. The Log Store supplies already-verified canonical
    /// blocks; this kernel operation owns output encryption and publication.
    pub fn compact_sealed(
        &self,
        mut blocks: Vec<CompactionBlock>,
    ) -> Result<CompactionPublication, LedgerFailure> {
        if blocks.is_empty() || blocks.len() > MAX_COMPACTION_BLOCKS {
            return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
        }
        if blocks.iter().any(|block| block.scope != self.scope) {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        blocks.sort_by_key(|block| block.position);
        if blocks
            .windows(2)
            .any(|pair| pair[0].position >= pair[1].position)
        {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
        state.require_healthy()?;
        self.catalog.refresh_state()?;
        let basis = self.catalog.pin()?;
        let current_metadata = self
            .storage
            .catalog_segments(&basis, self.scope)
            .map_err(|failure| LedgerFailure::new(failure.code()))?;
        let metadata_by_id = current_metadata
            .iter()
            .copied()
            .map(|metadata| (metadata.id, metadata))
            .collect::<BTreeMap<_, _>>();

        let mut selected_segments = BTreeSet::new();
        for block in &blocks {
            let Some(source) = state.blocks.iter().find(|candidate| {
                candidate.segment_id() == block.source_segment
                    && candidate.identity() == block.identity
                    && candidate.position() == block.position
            }) else {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            };
            if source.payload() != block.payload.as_slice()
                || source.content_digest()? != block.content_digest
            {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            }
            source
                .authenticate_ingest_time(block.ingest_time.instant())
                .map_err(|failure| LedgerFailure::new(failure.code()))?;
            let Some(metadata) = metadata_by_id.get(&block.source_segment) else {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            };
            if metadata.state != SegmentState::Sealed {
                return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
            }
            selected_segments.insert(block.source_segment);
        }

        for segment in &selected_segments {
            let expected = state
                .blocks
                .iter()
                .filter(|block| block.segment_id() == *segment)
                .count();
            let supplied = blocks
                .iter()
                .filter(|block| block.source_segment == *segment)
                .count();
            if expected != supplied {
                return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
            }
        }

        let block_bytes = blocks.iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.payload.len())
                .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
        })?;
        let claim = RecoveryWorkClaim::tenant(
            self.scope.tenant_id(),
            RecoveryWorkKind::EmergencyCompaction,
            super::capacity::compaction_claim(block_bytes, blocks.len())?,
        )
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let _capacity = self
            .authority
            .recovery()
            .reserve(claim)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        let runs = contiguous_runs(&blocks)?;
        let volume = self
            .authority
            .primary_data_volume()
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::StorageUnavailable))?;
        let mut output_storage = LedgerStorage::open(volume)?;
        let mut outputs = Vec::new();
        let mut output_blocks = Vec::new();
        for run in runs {
            let base = position_before(run[0].position)?;
            let metadata = fresh_metadata(self.scope, base)?;
            let key = match output_storage.create_active(
                metadata,
                &self.protection,
                self.catalog.instance(),
            ) {
                Ok(key) => key,
                Err(failure) => {
                    let cleanup = output_storage
                        .discard_unpublished(metadata)
                        .and_then(|()| discard_outputs(&output_storage, &outputs));
                    if let Err(cleanup_failure) = cleanup {
                        state.poisoned = true;
                        return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                    }
                    return Err(failure);
                },
            };
            let written = match write_run(&output_storage, &key, metadata.id, &run) {
                Ok(written) => written,
                Err(failure) => {
                    let cleanup = output_storage
                        .discard_unpublished(metadata)
                        .and_then(|()| discard_outputs(&output_storage, &outputs));
                    if let Err(cleanup_failure) = cleanup {
                        state.poisoned = true;
                        return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                    }
                    return Err(failure);
                },
            };
            outputs.push(SegmentMetadata {
                state: SegmentState::Sealed,
                ..metadata
            });
            output_blocks.extend(written);
        }

        let mut proposal = current_metadata;
        let compaction_frontier = blocks
            .last()
            .map(|block| block.position)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        for candidate in proposal.iter_mut() {
            if selected_segments.contains(&candidate.id) {
                // Every retired input is a continuity marker after the
                // replacement's complete frontier. Keeping per-input
                // positions would make reconstruction observe a retired
                // marker behind the replacement output.
                candidate.base_position = compaction_frontier;
                candidate.state = SegmentState::Retired;
            }
        }
        proposal.extend(outputs.iter().copied());
        let published =
            match publish_segments(self.catalog, &basis, &output_storage, self.scope, &proposal) {
                Ok(published) => published,
                Err(failure)
                    if failure.completion_state()
                        == super::LedgerCompletionState::RejectedBeforeMutation =>
                {
                    if let Err(cleanup_failure) = discard_outputs(&output_storage, &outputs) {
                        state.poisoned = true;
                        return Err(LedgerFailure::post_mutation(cleanup_failure.code()));
                    }
                    return Err(failure);
                },
                Err(failure) => {
                    // The publication helper has already reconciled any durable
                    // successor. A remaining ambiguous result must retain every
                    // output until restart can determine whether that successor
                    // was visible to a snapshot.
                    state.poisoned = true;
                    return Err(failure);
                },
            };
        for output in &outputs {
            if let Err(failure) = output_storage.seal(*output) {
                state.poisoned = true;
                return Err(LedgerFailure::ambiguous(failure.code()));
            }
        }

        state
            .blocks
            .retain(|block| !selected_segments.contains(&block.segment_id()));
        state.blocks.extend(output_blocks);
        state.blocks.sort_by_key(CommittedBlock::position);
        drop(published);
        Ok(CompactionPublication {
            input_segments: selected_segments.len(),
            output_segments: outputs.len(),
        })
    }
}

fn contiguous_runs(blocks: &[CompactionBlock]) -> Result<Vec<Vec<CompactionBlock>>, LedgerFailure> {
    let mut runs = Vec::new();
    for block in blocks {
        let append = runs.last_mut().filter(|run: &&mut Vec<CompactionBlock>| {
            run.last().is_some_and(|previous| {
                previous
                    .position
                    .value()
                    .checked_add(1)
                    .is_some_and(|next| next == block.position.value())
            })
        });
        if let Some(run) = append {
            run.push(block.clone());
        } else {
            let mut run = Vec::new();
            run.try_reserve(1)
                .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
            run.push(block.clone());
            runs.push(run);
        }
    }
    Ok(runs)
}

fn position_before(
    position: positron_domain::routing::CommitPosition,
) -> Result<positron_domain::routing::CommitPosition, LedgerFailure> {
    let value = position.value();
    if value == 0 {
        return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
    }
    let previous = value
        .checked_sub(1)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if previous == 0 {
        Ok(positron_domain::routing::CommitPosition::origin())
    } else {
        positron_domain::routing::CommitPosition::origin()
            .advance_by(
                NonZeroU64::new(previous)
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))
    }
}

fn write_run(
    storage: &LedgerStorage,
    key: &crate::data_protection::ObjectDataKey,
    segment: super::SegmentId,
    blocks: &[CompactionBlock],
) -> Result<Vec<CommittedBlock>, LedgerFailure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(blocks.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut retention = SegmentRetention::Empty;
    for (sequence, block) in blocks.iter().enumerate() {
        let sequence = u64::try_from(sequence)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        retention = retention.append_block(SegmentRetention::Complete(block.ingest_time));
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve_exact(
                25_usize
                    .checked_add(block.payload.len())
                    .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
            )
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
        plaintext.extend_from_slice(&block.identity.to_bytes());
        plaintext.push(2);
        plaintext.extend_from_slice(&block.ingest_time.instant().value().to_be_bytes());
        plaintext.extend_from_slice(&block.payload);
        let context = key
            .object
            .frame(
                SegmentFramePurpose::StoreBlock,
                FrameSequence::new(
                    sequence
                        .checked_add(1)
                        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?,
                ),
            )
            .map_err(super::map_frame_failure)?;
        let limits = FrameLimits::new(MAX_ENCODED_FRAME_BYTES).map_err(super::map_frame_failure)?;
        let frame_bytes = DataProtection::protected_frame_length(plaintext.len(), limits)
            .map_err(super::map_frame_failure)?;
        let authenticator = storage
            .append_and_commit(
                key,
                NextFrontier {
                    sequence,
                    position: block.position,
                    segment_retention: retention,
                },
                frame_bytes,
                || {
                    DataProtection::protect_frame(key, context, &plaintext, limits)
                        .map_err(super::map_frame_failure)
                },
                || Ok(()),
            )
            .map_err(map_append_failure)?;
        output.push(CommittedBlock {
            identity: block.identity,
            position: block.position,
            payload: block.payload.clone(),
            content_digest: block.content_digest,
            segment,
            frontier_authenticator: authenticator,
            block_retention: SegmentRetention::Complete(block.ingest_time),
        });
    }
    Ok(output)
}

fn map_append_failure(failure: AppendFailure) -> LedgerFailure {
    match failure {
        AppendFailure::RejectedBeforeMutation(failure) | AppendFailure::SegmentMutated(failure) => {
            failure
        },
    }
}

fn discard_outputs(
    storage: &LedgerStorage,
    outputs: &[SegmentMetadata],
) -> Result<(), LedgerFailure> {
    for metadata in outputs {
        storage.discard_unpublished(*metadata)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_before_rejects_the_origin_position() {
        let failure = position_before(positron_domain::routing::CommitPosition::origin())
            .expect_err("the origin has no predecessor");
        assert_eq!(failure.code(), LedgerFailureCode::InvalidInput);
    }
}
