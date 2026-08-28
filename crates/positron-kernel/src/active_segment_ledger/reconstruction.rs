use crate::catalog::InstanceId;
use crate::data_protection::ObjectDataKey;
use positron_domain::routing::CommitPosition;

use super::format::{SegmentMetadata, SegmentState};
use super::recovery::RecoveryMode;
use super::state::retain_recovered;
use super::storage::LedgerStorage;
use super::{CommittedBlock, LedgerFailure, LedgerFailureCode, SegmentProtectionKey};

/// The common authenticated reconstruction result used by writer recovery and
/// observation-only readers. It contains no open file handles.
pub(super) struct Reconstruction {
    pub(super) blocks: Vec<CommittedBlock>,
    pub(super) retained_bytes: usize,
    pub(super) frontier: CommitPosition,
    pub(super) recovered_active: Option<(SegmentMetadata, ObjectDataKey)>,
}

pub(super) fn reconstruct(
    storage: &LedgerStorage,
    metadata: &[SegmentMetadata],
    protection: &SegmentProtectionKey,
    instance: InstanceId,
    mode: RecoveryMode,
) -> Result<Reconstruction, LedgerFailure> {
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
        while let Some(segment) = segments.next_if(|candidate| candidate.base_position == base) {
            let (key, recovered) =
                storage.recover_segment_with_mode(segment, protection, instance, mode)?;
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

    Ok(Reconstruction {
        blocks,
        retained_bytes,
        frontier,
        recovered_active,
    })
}
