use std::collections::{BTreeMap, BTreeSet};

use super::capacity::retained_claim;
use super::format::SegmentState;
use super::publication::publish_segments;
use super::{
    ActiveSegmentLedger, BlockRetentionEvidence, LedgerFailure, LedgerFailureCode,
    RecoveryWorkClaim, RecoveryWorkKind, RetentionReclamation,
};

/// Derives fully expired sealed segments from snapshot-bound block evidence,
/// then publishes only those complete segments as retired.
pub(super) fn retire_expired_sealed_segments(
    ledger: &ActiveSegmentLedger<'_, '_>,
    cutoff: crate::RetentionCutoff,
    evidence: &[BlockRetentionEvidence],
) -> Result<RetentionReclamation, LedgerFailure> {
    if evidence.len() > super::MAX_RETAINED_BLOCKS {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let mut state = ledger
        .state
        .lock()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
    ledger.catalog.refresh_state()?;
    let basis = ledger.catalog.pin()?;
    let mut inspected_bytes = 0_usize;
    for item in evidence {
        if item.scope != ledger.scope
            || item.catalog_identity != basis.identity()
            || item.bucket.tenant() != ledger.scope.tenant
            || item.bucket.signal_kind() != ledger.scope.signal
        {
            return Err(LedgerFailure::new(LedgerFailureCode::PhysicalScopeMismatch));
        }
        let Some(block) = state.blocks.iter().find(|block| {
            block.identity == item.block
                && block.segment == item.segment
                && block.content_digest == item.content_digest
        }) else {
            return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
        };
        inspected_bytes = inspected_bytes
            .checked_add(block.payload.len())
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    }
    let catalog_items = basis.plaintext_object_count();
    let inspected_bytes = super::format::METADATA_BYTES
        .checked_mul(catalog_items)
        .and_then(|metadata_bytes| inspected_bytes.checked_add(metadata_bytes))
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let inspected_items = evidence
        .len()
        .checked_add(catalog_items)
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let claim = RecoveryWorkClaim::tenant(
        ledger.scope.tenant,
        RecoveryWorkKind::Retention,
        super::capacity::retention_claim(inspected_bytes, inspected_items)?,
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let _retention = ledger
        .authority
        .recovery()
        .reserve(claim)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut by_block = BTreeMap::new();
    for item in evidence {
        if by_block.insert(item.block, *item).is_some() {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
    }
    let mut metadata = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let mut retired = BTreeSet::new();
    for candidate in metadata
        .iter_mut()
        .filter(|candidate| candidate.state == SegmentState::Sealed)
    {
        let mut segment_blocks = state
            .blocks
            .iter()
            .filter(|block| block.segment == candidate.id)
            .peekable();
        if segment_blocks.peek().is_none() {
            candidate.state = SegmentState::Retired;
            retired.insert(candidate.id);
            continue;
        }
        let mut latest: Option<crate::IngestTime> = None;
        let mut complete = true;
        for block in segment_blocks {
            let Some(item) = by_block.get(&block.identity) else {
                complete = false;
                break;
            };
            latest = Some(latest.map_or(item.latest_ingest_time, |current| {
                current.max(item.latest_ingest_time)
            }));
        }
        if !complete
            || latest.is_none_or(|latest| latest.instant().value() > cutoff.instant().value())
        {
            continue;
        }
        // A retired segment no longer participates in reconstruction, so its
        // catalog position carries the authenticated continuity point needed
        // to resume the following segment after a restart.
        candidate.base_position = state
            .blocks
            .iter()
            .filter(|block| block.segment_id() == candidate.id)
            .map(|block| block.position())
            .max()
            .map_or(candidate.base_position, |position| position);
        candidate.state = SegmentState::Retired;
        retired.insert(candidate.id);
    }

    if !retired.is_empty() {
        publish_segments(
            ledger.catalog,
            &basis,
            &ledger.storage,
            ledger.scope,
            &metadata,
        )
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    }

    if !retired.is_empty() {
        state
            .blocks
            .retain(|block| !retired.contains(&block.segment));
        state.retained_bytes = state
            .blocks
            .iter()
            .try_fold(0_usize, |total, block| {
                total.checked_add(block.payload.len())
            })
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
        let remaining_capacity = retained_claim(state.retained_bytes, state.blocks.len())?;
        state
            .retained_capacity
            .try_resize_preserving_capacity(remaining_capacity)
            .map_err(|_| LedgerFailure::new(LedgerFailureCode::RecoveryRequired))?;
    }
    let now = cutoff
        .evaluated_at()
        .value()
        .checked_div(1_000_000_000)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let physically_reclaimed_segments = reclaim_retired_segments(ledger, now)?;
    Ok(RetentionReclamation {
        logically_retired_segments: retired.len(),
        physically_reclaimed_segments,
    })
}

fn reclaim_retired_segments(
    ledger: &ActiveSegmentLedger<'_, '_>,
    now: u64,
) -> Result<usize, LedgerFailure> {
    let _barrier = super::snapshot_protection::SnapshotProtection::write_barrier(
        ledger.authority.snapshot_barrier(),
    )?;
    let basis = ledger.catalog.pin()?;
    let metadata = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let leased = super::snapshot_lease::active_segments(&basis, ledger.scope, now)?;
    let registry = ledger.authority.snapshot_protection();
    let mut reclaimable = Vec::new();
    reclaimable
        .try_reserve_exact(metadata.len())
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    for candidate in metadata.iter().copied().filter(|candidate| {
        candidate.state == SegmentState::Retired && !leased.contains(&candidate.id)
    }) {
        if !super::snapshot_protection::SnapshotProtection::is_protected(&registry, candidate.id)? {
            reclaimable.push(candidate);
        }
    }
    if reclaimable.is_empty() {
        return Ok(0);
    }
    for candidate in &reclaimable {
        ledger.storage.reclaim_retired(*candidate)?;
    }
    let basis = ledger.catalog.pin()?;
    let mut remaining = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let continuity_marker = reclaimable
        .iter()
        .copied()
        .max_by_key(|candidate| candidate.base_position);
    remaining.retain(|candidate| !reclaimable.iter().any(|retired| retired.id == candidate.id));
    if let Some(marker) = continuity_marker {
        remaining.push(marker);
    }
    publish_segments(
        ledger.catalog,
        &basis,
        &ledger.storage,
        ledger.scope,
        &remaining,
    )
    .map_err(|failure| LedgerFailure::new(failure.code()))?;
    Ok(reclaimable.len())
}
