use positron_domain::routing::CommitPosition;
use std::collections::BTreeMap;

use crate::ResourceReservation;

use super::recovery::RecoveryState;
use super::{
    CommitReceipt, CommittedBlock, LedgerFailure, LedgerFailureCode, MAX_RETAINED_BLOCK_BYTES,
};

pub(super) struct LedgerState<'kernel> {
    pub(super) _capacity: ResourceReservation<'kernel>,
    pub(super) retained_reservations: Vec<ResourceReservation<'kernel>>,
    pub(super) frontier: CommitPosition,
    pub(super) blocks: Vec<CommittedBlock>,
    pub(super) retained_bytes: usize,
    pub(super) next_sequence: u64,
    pub(super) poisoned: bool,
    pub(super) lease_reservations: BTreeMap<super::SnapshotLeaseId, ResourceReservation<'kernel>>,
    pub(super) last_snapshot_lease_time: u64,
}

pub(super) fn receipt_for(block: &CommittedBlock) -> CommitReceipt {
    CommitReceipt {
        segment: block.segment,
        position: block.position,
        frontier_authenticator: block.frontier_authenticator,
    }
}

pub(super) fn retain_recovered(
    recovered: RecoveryState,
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
        .filter(|bytes| {
            *bytes <= MAX_RETAINED_BLOCK_BYTES && block_count <= super::MAX_RETAINED_BLOCKS
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    *frontier = recovered.frontier;
    blocks.extend(recovered.blocks);
    Ok(())
}
