use positron_kernel::SnapshotLeaseGrant;

use super::super::cursor::{TailCursor, TailCursorState, TailSourceBinding};
use super::super::source::TailSourceSet;
use super::super::terminal::{TailStats, TailTerminal};
use crate::{QueryFailure, QueryFailureCode};

pub(super) fn validate_resume_history(
    state: &TailCursorState,
    sources: &TailSourceSet<'_, '_, '_>,
) -> Result<(), QueryFailure> {
    for reader in sources.readers() {
        let snapshot = reader
            .snapshot()
            .map_err(crate::execution_support::map_ledger_failure)?;
        let Some((position_index, position)) = state
            .positions()
            .iter()
            .enumerate()
            .find(|(_, position)| position.shard() == snapshot.scope().shard_id())
        else {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        };
        if position.position() > snapshot.frontier() {
            return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        }
        if let Some(markers) = state.historical_markers() {
            let marker = markers
                .get(position_index)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            if marker.handoff_frontier() > snapshot.frontier()
                || (marker.handoff_frontier() > marker.lower_bound()
                    && !snapshot.blocks().iter().any(|block| {
                        block.position() >= marker.lower_bound()
                            && block.position() <= marker.handoff_frontier()
                    }))
            {
                return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
            }
        } else if state.record_bound()
            && position.position() != positron_domain::routing::CommitPosition::origin()
            && !snapshot
                .blocks()
                .iter()
                .any(|block| block.position() == position.position())
        {
            return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        }
    }
    Ok(())
}

pub(super) fn resume_source_lease<'kernel, 'catalog, 'ledger>(
    authority: &'ledger positron_kernel::ActiveSegmentLedger<'kernel, 'catalog>,
    binding: TailSourceBinding,
    state: &TailCursorState,
    now: u64,
    expected_catalog: Option<(positron_kernel::CatalogGenerationId, u64)>,
) -> Result<SnapshotLeaseGrant<'kernel>, QueryFailure> {
    let now = now.max(
        authority
            .snapshot_lease_time()
            .map_err(crate::execution_support::map_ledger_failure)?,
    );
    let grant = match expected_catalog {
        Some((identity, generation)) => authority.resume_snapshot_lease_with_marker_at_catalog(
            binding.lease(),
            now,
            state.sequence(),
            state.prior_digest(),
            identity,
            generation,
        ),
        None => authority.resume_snapshot_lease_with_marker(
            binding.lease(),
            now,
            state.sequence(),
            state.prior_digest(),
        ),
    }
    .map_err(crate::execution_support::map_ledger_failure)?;
    let snapshot = grant.snapshot();
    if snapshot.scope().shard_id() != binding.shard()
        || snapshot.frontier() != binding.frontier()
        || expected_catalog.is_some()
            && (snapshot.catalog_identity().to_bytes() != state.snapshot_identity()
                || snapshot.catalog_generation() != state.snapshot_generation())
    {
        return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
    }
    Ok(grant)
}

pub(super) fn validate_resume_leases(
    state: &TailCursorState,
    sources: &TailSourceSet<'_, '_, '_>,
    now: u64,
    primary_shard: positron_domain::routing::VirtualShardId,
) -> Result<(), QueryFailure> {
    for reader in sources.readers() {
        let binding = state
            .source_binding(reader.scope().shard_id())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
        let authority = reader
            .lease_authority()
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
        let lease_now = now.max(
            authority
                .snapshot_lease_time()
                .map_err(crate::execution_support::map_ledger_failure)?,
        );
        let grant = authority
            .resume_snapshot_lease(binding.lease(), lease_now)
            .map_err(|failure| {
                if failure.code() == positron_kernel::LedgerFailureCode::SnapshotExpired {
                    QueryFailure::new(QueryFailureCode::StoreUnavailable)
                } else {
                    crate::execution_support::map_ledger_failure(failure)
                }
            })?;
        let snapshot = grant.snapshot();
        if snapshot.scope().shard_id() != binding.shard()
            || snapshot.frontier() != binding.frontier()
            || (snapshot.scope().shard_id() == primary_shard
                && (snapshot.catalog_identity().to_bytes() != state.snapshot_identity()
                    || snapshot.catalog_generation() != state.snapshot_generation()))
        {
            return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        }
    }
    Ok(())
}

pub(in crate::tail) fn terminal_for_failure(
    code: QueryFailureCode,
    cursor: Option<TailCursor>,
    stats: TailStats,
) -> TailTerminal {
    match code {
        QueryFailureCode::BudgetExhausted => TailTerminal::BudgetExhausted { cursor, stats },
        QueryFailureCode::Cancelled => TailTerminal::Cancelled { cursor, stats },
        QueryFailureCode::SnapshotExpired => TailTerminal::Expired { cursor, stats },
        QueryFailureCode::AuthorizationChanged => {
            TailTerminal::AuthorizationChanged { cursor, stats }
        },
        _ => TailTerminal::StoreUnavailable { cursor, stats },
    }
}
