use std::collections::BTreeSet;

use super::format::SegmentState;
use super::publication::publish_segments;
use super::{
    ActiveSegmentLedger, LedgerFailure, LedgerFailureCode, RecoveryWorkClaim, RecoveryWorkKind,
    RetentionReclamation, SegmentId,
};

/// Publishes whole sealed segments as retired for one ledger scope.
pub(super) fn retire_sealed_segments(
    ledger: &ActiveSegmentLedger<'_, '_>,
    segments: &[SegmentId],
    now: u64,
) -> Result<RetentionReclamation, LedgerFailure> {
    if segments.len() > super::MAX_RETAINED_BLOCKS {
        return Err(LedgerFailure::new(LedgerFailureCode::LimitExceeded));
    }
    let claim = RecoveryWorkClaim::tenant(
        ledger.scope.tenant,
        RecoveryWorkKind::Retention,
        super::capacity::retention_claim(),
    )
    .map_err(|_| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let _retention = ledger
        .authority
        .recovery()
        .reserve(claim)
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ResourceAdmissionRefused))?;
    let mut requested = BTreeSet::new();
    for segment in segments {
        if !requested.insert(*segment) {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
    }
    if requested.is_empty() {
        let physically_reclaimed_segments = reclaim_retired_segments(ledger, now)?;
        return Ok(RetentionReclamation {
            logically_retired_segments: 0,
            physically_reclaimed_segments,
        });
    }

    let mut state = ledger
        .state
        .lock()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
    ledger.catalog.refresh_state()?;
    let basis = ledger.catalog.pin()?;
    let mut metadata = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let mut retired = BTreeSet::new();
    for segment in requested {
        let candidate = metadata
            .iter_mut()
            .find(|metadata| metadata.id == segment)
            .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::InvalidInput))?;
        if candidate.scope != ledger.scope || candidate.state != SegmentState::Sealed {
            return Err(LedgerFailure::new(LedgerFailureCode::InvalidInput));
        }
        // A retired segment no longer participates in reconstruction, so its
        // catalog position carries the authenticated continuity point needed
        // to resume the following segment after a restart.
        candidate.base_position = state
            .blocks
            .iter()
            .filter(|block| block.segment_id() == segment)
            .map(|block| block.position())
            .max()
            .map_or(candidate.base_position, |position| position);
        candidate.state = SegmentState::Retired;
        retired.insert(segment);
    }

    publish_segments(
        ledger.catalog,
        &basis,
        &ledger.storage,
        ledger.scope,
        &metadata,
    )
    .map_err(|failure| LedgerFailure::new(failure.code()))?;

    state
        .blocks
        .retain(|block| !retired.contains(&block.segment));
    let mut retained_reservations = Vec::with_capacity(state.retained_reservations.len());
    let mut release_failure = false;
    for (segment, mut reservation) in state.retained_reservations.drain(..) {
        if retired.contains(&segment) {
            if reservation.cancel().is_err() {
                release_failure = true;
            }
        } else {
            retained_reservations.push((segment, reservation));
        }
    }
    state.retained_reservations = retained_reservations;
    state.retained_bytes = state
        .blocks
        .iter()
        .try_fold(0_usize, |total, block| {
            total.checked_add(block.payload.len())
        })
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    if release_failure {
        return Err(LedgerFailure::new(
            LedgerFailureCode::ResourceAdmissionRefused,
        ));
    }
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
