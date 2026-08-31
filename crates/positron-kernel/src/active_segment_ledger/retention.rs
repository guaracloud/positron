use std::collections::BTreeSet;

use super::capacity::retained_claim;
use super::format::SegmentState;
use super::publication::{publish_exact_scope_segments, publish_segments_with_frontier};
use super::{
    ActiveSegmentLedger, LedgerCompletionState, LedgerFailure, LedgerFailureCode,
    RetentionEvaluation, RetentionReclamation, SegmentRetention,
};

pub(super) fn commit(
    evaluation: RetentionEvaluation<'_, '_, '_>,
) -> Result<RetentionReclamation, LedgerFailure> {
    let ledger = evaluation.ledger;
    let mut state = ledger
        .state
        .lock()
        .map_err(|_| LedgerFailure::new(LedgerFailureCode::ConcurrentWriter))?;
    state.require_healthy()?;
    ledger.catalog.refresh_state()?;
    let basis = ledger.catalog.pin()?;
    let current_policy = basis.log_retention_policy()?;
    if current_policy != evaluation.policy {
        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
    }
    if state.retention_frontier != evaluation.expected_retention_frontier
        || state.retention_readiness != evaluation.expected_retention_readiness
    {
        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
    }
    if state.blocks != evaluation.blocks {
        return Err(LedgerFailure::new(LedgerFailureCode::StaleGeneration));
    }
    let mut metadata = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| LedgerFailure::new(failure.code()))?;
    let mut newly_retired = BTreeSet::new();
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
            newly_retired.insert(candidate.id);
            continue;
        }
        let mut latest = None;
        for block in segment_blocks {
            match block.block_retention {
                SegmentRetention::Complete(instant) => {
                    latest = Some(
                        latest.map_or(instant, |current: crate::IngestTime| current.max(instant)),
                    );
                },
                SegmentRetention::Empty | SegmentRetention::Unavailable => {
                    return Err(LedgerFailure::new(LedgerFailureCode::UnsupportedFormat));
                },
            }
        }
        if latest.is_none_or(|latest| latest.instant().value() > evaluation.cutoff.value()) {
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
        newly_retired.insert(candidate.id);
    }
    let now = evaluation
        .frontier
        .instant()
        .value()
        .checked_div(1_000_000_000)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| LedgerFailure::new(LedgerFailureCode::LimitExceeded))?;
    let latest = match publish_segments_with_frontier(
        ledger.catalog,
        &basis,
        &ledger.storage,
        ledger.scope,
        &metadata,
        evaluation.frontier,
    ) {
        Ok(latest) => latest,
        Err(failure) => {
            if failure.completion_state() != super::LedgerCompletionState::RejectedBeforeMutation {
                state.poisoned = true;
            }
            return Err(failure);
        },
    };
    let latest_metadata = ledger
        .storage
        .catalog_segments(&latest, ledger.scope)
        .map_err(|failure| poison_after_commit(&mut state, failure))?;
    let retired = latest_metadata
        .iter()
        .filter(|candidate| candidate.state == SegmentState::Retired)
        .map(|candidate| candidate.id)
        .collect::<BTreeSet<_>>();
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
            .ok_or_else(|| {
                poison_after_commit(
                    &mut state,
                    LedgerFailure::new(LedgerFailureCode::LimitExceeded),
                )
            })?;
        let remaining_capacity = retained_claim(state.retained_bytes, state.blocks.len())
            .map_err(|failure| poison_after_commit(&mut state, failure))?;
        if state
            .retained_capacity
            .try_resize_preserving_capacity(remaining_capacity)
            .is_err()
        {
            state.poisoned = true;
            return Err(LedgerFailure::post_mutation(
                LedgerFailureCode::RecoveryRequired,
            ));
        }
    }
    state.retention_frontier = Some(evaluation.frontier);
    state.retention_readiness = super::state::RetentionReadiness::TrustedPersisted;
    let physically_reclaimed_segments = match reclaim_retired_segments(ledger, now) {
        Ok(reclaimed) => reclaimed,
        Err(failure) => {
            return Err(poison_after_commit(&mut state, failure));
        },
    };
    Ok(RetentionReclamation {
        logically_retired_segments: newly_retired.len(),
        physically_reclaimed_segments,
        evaluated_at: evaluation.frontier.instant(),
    })
}

fn poison_after_commit(
    state: &mut super::state::LedgerState,
    failure: LedgerFailure,
) -> LedgerFailure {
    state.poisoned = true;
    if failure.completion_state() == LedgerCompletionState::RejectedBeforeMutation {
        LedgerFailure::post_mutation(failure.code())
    } else {
        failure
    }
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
    let mut physically_mutated = false;
    for candidate in &reclaimable {
        match ledger.storage.reclaim_retired(*candidate) {
            Ok(changed) => physically_mutated |= changed,
            Err(failure) if physically_mutated => {
                return Err(LedgerFailure::post_mutation(failure.code()));
            },
            Err(failure) => return Err(failure),
        }
    }
    let basis = ledger
        .catalog
        .pin()
        .map_err(LedgerFailure::from)
        .map_err(|failure| after_physical_reclamation(failure, physically_mutated))?;
    let mut remaining = ledger
        .storage
        .catalog_segments(&basis, ledger.scope)
        .map_err(|failure| after_physical_reclamation(failure, physically_mutated))?;
    let continuity_marker = reclaimable
        .iter()
        .copied()
        .max_by_key(|candidate| candidate.base_position);
    remaining.retain(|candidate| !reclaimable.iter().any(|retired| retired.id == candidate.id));
    if let Some(marker) = continuity_marker {
        remaining.push(marker);
    }
    publish_exact_scope_segments(
        ledger.catalog,
        &basis,
        &ledger.storage,
        ledger.scope,
        &remaining,
    )
    .map_err(|failure| after_physical_reclamation(failure, physically_mutated))?;
    Ok(reclaimable.len())
}

fn after_physical_reclamation(failure: LedgerFailure, physically_mutated: bool) -> LedgerFailure {
    if physically_mutated {
        LedgerFailure::post_mutation(failure.code())
    } else {
        failure
    }
}
