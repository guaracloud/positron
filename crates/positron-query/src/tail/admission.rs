use positron_kernel::SnapshotLeaseGrant;

use crate::stream::{QueryHeader, ResultLease, ResultSnapshot};
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{
    HistoricalMarker, TailCursor, TailCursorState, TailPosition, TailSourceBinding, budget_digest,
};
use super::lease::{TailLeaseOwner, TailLeaseSet};
use super::session::{TailSession, TailStart};
use super::source::TailSourceSet;
#[path = "admission_resume.rs"]
mod resume;
pub(super) use resume::terminal_for_failure;
use resume::{resume_source_lease_for_tail as resume_source_lease, validate_resume_leases};
#[path = "admission_api.rs"]
mod api;

pub(super) fn validate_tail_shape(
    query: &PlannedQuery<'_>,
    sources: &TailSourceSet<'_, '_, '_>,
    tenant: positron_domain::identity::TenantId,
    ledger_scope: positron_kernel::SegmentScope,
) -> Result<(), QueryFailure> {
    if query.cancellation.is_cancelled() {
        return Err(QueryFailure::new(QueryFailureCode::Cancelled));
    }
    if sources.tenant() != tenant {
        return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
    }
    if query.plan.tail_incompatible()
        || query.plan.has_total_limit()
        || query.plan.has_explicit_ordering()
        || !sources
            .readers()
            .iter()
            .any(|reader| reader.scope() == ledger_scope)
    {
        return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
    }
    Ok(())
}

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub(super) fn admit_tail(
        &self,
        query: PlannedQuery<'kernel>,
        start: TailStart,
        resume: Option<(TailCursorState, TailCursor)>,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let (tenant, catalog_identity, generation) = self.current_query_catalog(query.context)?;
        validate_tail_shape(&query, &sources, tenant, self.ledger.scope())?;
        let now = self.now()?;
        let expiry = resume.as_ref().map_or_else(
            || {
                query
                    .started_at
                    .checked_add(query.budget.wall_seconds())
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))
            },
            |(state, _)| Ok(state.expiry()),
        )?;
        if now >= expiry {
            return Err(QueryFailure::new(QueryFailureCode::SnapshotExpired));
        }
        if let TailStart::Historical { max_rows } = start
            && (max_rows == 0 || max_rows > super::MAX_TAIL_BATCH_ROWS)
        {
            return Err(QueryFailure::new(QueryFailureCode::InvalidBudget));
        }
        if let Some((state, _)) = resume.as_ref() {
            if state.source_bindings().is_none() {
                return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
            }
            validate_resume_leases(state, &sources, now, self.ledger.scope().shard_id())?;
        }
        let mut source_lease_owners = TailLeaseSet::with_capacity(sources.readers().len())?;
        let mut source_lease_grants = Vec::new();
        source_lease_grants
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut source_lease_ids = Vec::new();
        let mut source_frontiers = Vec::new();
        source_lease_ids
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        source_frontiers
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let (lease, lease_owner) = if let Some((state, _)) = resume.as_ref() {
            let primary_shard = self.ledger.scope().shard_id();
            let binding = state
                .source_binding(primary_shard)
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            let lease = resume_source_lease(
                self.ledger,
                binding,
                state,
                now,
                Some((catalog_identity, generation)),
            )?;
            let owner = TailLeaseOwner::new(self.ledger, lease.identity());
            (lease, owner)
        } else {
            let lease = self
                .ledger
                .create_snapshot_lease_at_catalog(now, expiry, catalog_identity)
                .map_err(crate::execution_support::map_ledger_failure)?;
            let owner = TailLeaseOwner::new(self.ledger, lease.identity());
            (lease, owner)
        };
        for reader in sources.readers() {
            let shard = reader.scope().shard_id();
            let (authority, source_lease) = if reader.scope() == self.ledger.scope() {
                (self.ledger, None)
            } else if let Some((state, _)) = resume.as_ref() {
                let binding = state
                    .source_binding(shard)
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
                let authority = reader
                    .lease_authority()
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                let source_lease = resume_source_lease(authority, binding, state, now, None)?;
                (authority, Some(source_lease))
            } else {
                let authority = reader
                    .lease_authority()
                    .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
                let source_lease = authority
                    .create_snapshot_lease(now, expiry)
                    .map_err(crate::execution_support::map_ledger_failure)?;
                (authority, Some(source_lease))
            };
            let lease_id = source_lease
                .as_ref()
                .map_or_else(|| lease.identity(), SnapshotLeaseGrant::identity);
            source_lease_ids.push((shard, lease_id));
            let frontier = source_lease.as_ref().map_or_else(
                || lease.snapshot().frontier(),
                |grant| grant.snapshot().frontier(),
            );
            source_frontiers.push((shard, frontier));
            if let Some(source_lease) = source_lease {
                source_lease_owners.push(TailLeaseOwner::new(authority, source_lease.identity()));
                source_lease_grants.push(source_lease);
            }
        }
        let mut frontiers = Vec::new();
        frontiers
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut header_snapshot = Some(lease.snapshot());
        for reader in sources.readers() {
            let shard = reader.scope().shard_id();
            let frontier = source_frontiers
                .iter()
                .find(|(candidate, _)| *candidate == shard)
                .map(|(_, frontier)| *frontier)
                .ok_or_else(super::internal)?;
            if reader.scope() == self.ledger.scope() {
                // The primary grant is the authoritative snapshot used for the
                // response header. It was captured at the same catalog basis as
                // every source grant above.
                header_snapshot = Some(lease.snapshot());
            }
            frontiers.push((shard, frontier));
        }
        let snapshot = header_snapshot.ok_or_else(super::internal)?;
        frontiers.sort_unstable_by_key(|(shard, _)| *shard);
        let digest = sources.digest(&self.ledger.control_tokens())?;
        let expected_budget = budget_digest(&self.ledger.control_tokens(), query.budget)?;
        let resumed = resume.is_some();
        let (mut state, cursor, replay, replay_delivery) = match resume {
            Some((mut state, _cursor)) => {
                if state.positions().len() != sources.readers().len()
                    || state
                        .positions()
                        .iter()
                        .any(|position| !sources.contains(position.shard()))
                {
                    return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
                }
                let replay_delivery = state.unacknowledged_delivery();
                if replay_delivery.is_some_and(|(sequence, _)| sequence != state.sequence()) {
                    return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
                }
                let replay = replay_delivery.is_some();
                state.clear_unacknowledged_delivery();
                state.validate_budget(expected_budget)?;
                let cursor = TailCursor::encode(&self.ledger.control_tokens(), &state)?;
                (state, cursor, replay, replay_delivery)
            },
            None => {
                let mut positions = Vec::new();
                positions
                    .try_reserve_exact(frontiers.len())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                for (shard, frontier) in &frontiers {
                    positions.push(TailPosition::new(
                        *shard,
                        match start {
                            TailStart::Now => *frontier,
                            TailStart::Historical { .. } => {
                                positron_domain::routing::CommitPosition::origin()
                            },
                        },
                    ));
                }
                let mut state = TailCursorState::new(
                    query.context.principal_id(),
                    tenant,
                    query.context.authorization_generation(),
                    query.plan_digest,
                    digest,
                    positions,
                    expiry,
                    0,
                    [0; 32],
                )?;
                state.set_budget_digest(expected_budget);
                if matches!(start, TailStart::Historical { .. }) {
                    let mut markers = Vec::new();
                    markers
                        .try_reserve_exact(frontiers.len())
                        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                    for (_, frontier) in &frontiers {
                        markers.push(HistoricalMarker::new(
                            positron_domain::routing::CommitPosition::origin(),
                            *frontier,
                        )?);
                    }
                    state.set_historical_markers(markers)?;
                }
                let mut bindings = Vec::new();
                bindings
                    .try_reserve_exact(frontiers.len())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                for (shard, frontier) in &frontiers {
                    let lease = source_lease_ids
                        .iter()
                        .find(|(candidate, _)| candidate == shard)
                        .map(|(_, lease)| *lease)
                        .ok_or_else(super::internal)?;
                    bindings.push(TailSourceBinding::new(*shard, lease, *frontier));
                }
                state.set_source_bindings(catalog_identity.to_bytes(), generation, bindings)?;
                let cursor = TailCursor::encode(&self.ledger.control_tokens(), &state)?;
                (state, cursor, false, None)
            },
        };
        let max_rows = match start {
            TailStart::Historical { max_rows } => max_rows,
            TailStart::Now => 1,
        };
        let retain_source_grants =
            matches!(start, TailStart::Historical { .. }) || state.historical_markers().is_some();
        let maximum_records = usize::try_from(query.budget.output_rows())
            .map_err(|_| QueryFailure::new(QueryFailureCode::InvalidBudget))?
            .min(super::MAX_TAIL_BATCH_ROWS);
        let buffer = TailBuffer::new(
            maximum_records,
            query.budget.output_bytes(),
            query.budget.memory_bytes(),
        )?;
        let header = QueryHeader::new(
            &query.plan,
            query.budget,
            ResultSnapshot::new(
                catalog_identity.to_bytes(),
                generation,
                snapshot.frontier().value(),
            ),
            ResultLease::new(lease.identity().to_bytes(), expiry),
            None,
        )?;
        let (
            next_sequence,
            prior_digest,
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            cpu_work_units,
            memory_peak_bytes,
            elapsed_seconds,
            reduced_pruning,
            limiting_budget,
        ) = (
            state.sequence(),
            state.prior_digest(),
            state.scanned_bytes(),
            state.decoded_records(),
            state.output_rows(),
            state.output_bytes(),
            state.cpu_work_units(),
            state.memory_peak_bytes(),
            state.elapsed_seconds(),
            state.reduced_pruning(),
            state.limiting_budget(),
        );
        let (resume_count, repeated_batch_count, cursor) = if resumed {
            let resume_count = state
                .resume_count()
                .checked_add(1)
                .ok_or_else(super::internal)?;
            let repeated_batch_count = state
                .repeated_batch_count()
                .checked_add(u64::from(replay))
                .ok_or_else(super::internal)?;
            state.set_resume_stats(resume_count, repeated_batch_count);
            let cursor = super::cursor::TailCursor::encode(&self.ledger.control_tokens(), &state)?;
            (resume_count, repeated_batch_count, cursor)
        } else {
            (state.resume_count(), state.repeated_batch_count(), cursor)
        };
        let historical_frontiers = if let Some(markers) = state.historical_markers() {
            let mut positions = Vec::new();
            positions
                .try_reserve_exact(markers.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            for ((shard, _), marker) in frontiers.iter().zip(markers) {
                positions.push(TailPosition::new(*shard, marker.handoff_frontier()));
            }
            positions
        } else {
            Vec::new()
        };
        let elapsed_anchor = query.last_observed_at;
        let mut session = TailSession {
            service: self,
            query,
            sources,
            _lease: Some(lease),
            lease_owner,
            source_lease_owners,
            source_lease_grants: if retain_source_grants {
                source_lease_grants
            } else {
                Vec::new()
            },
            state,
            cursor,
            header: Some(header),
            buffer,
            pending_batch: None,
            delivery_cursor: None,
            historical_frontiers,
            terminal: None,
            terminal_emitted: false,
            next_sequence,
            prior_digest,
            replay,
            replay_delivery,
            last_acknowledged: None,
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            cpu_work_units,
            memory_peak_bytes,
            elapsed_seconds,
            elapsed_anchor,
            reduced_pruning,
            limiting_budget,
            resume_count,
            repeated_batch_count,
            cursor_observed: std::cell::Cell::new(false),
        };
        if matches!(start, TailStart::Historical { .. }) {
            session.fill_sources(max_rows)?;
        }
        Ok(session)
    }
}
