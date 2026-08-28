use positron_kernel::SnapshotLeaseGrant;

use crate::stream::{QueryHeader, ResultLease, ResultSnapshot, TailPhase};
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{
    HistoricalMarker, TailCursor, TailCursorState, TailPosition, TailSourceBinding, budget_digest,
};
use super::lease::{TailLeaseOwner, TailLeaseSet};
use super::memory::tail_memory_budget;
use super::session::{TailSession, TailStart};
use super::source::TailSourceSet;
#[path = "admission_resume.rs"]
mod resume;
pub(super) use resume::terminal_for_failure;
use resume::{resume_source_lease, validate_resume_leases};
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
        || !sources.contains(ledger_scope.shard_id())
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
        mut resume: Option<(TailCursorState, TailCursor)>,
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
        let memory_budget = tail_memory_budget(&query)?;
        let mut source_lease_owners = TailLeaseSet::with_capacity(sources.readers().len())?;
        let mut source_lease_grants = Vec::new();
        source_lease_grants
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut bindings = Vec::new();
        bindings
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let (mut lease, lease_owner) = if let Some((state, _)) = resume.as_ref() {
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
        let lease_usage_before = lease.usage();
        let lease_attempt = lease.take_attempt();
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
            let frontier = source_lease.as_ref().map_or_else(
                || lease.snapshot().frontier(),
                |grant| grant.snapshot().frontier(),
            );
            bindings.push(TailSourceBinding::new(shard, lease_id, frontier));
            if let Some(source_lease) = source_lease {
                source_lease_owners.push(TailLeaseOwner::new(authority, source_lease.identity()));
                source_lease_grants.push(source_lease);
            }
        }
        let snapshot = lease.snapshot();
        let digest = sources.digest(&self.ledger.control_tokens())?;
        let expected_budget = budget_digest(&self.ledger.control_tokens(), query.budget)?;
        let resumed = resume.is_some();
        if let Some((state, _)) = resume.as_mut() {
            state.set_progress(
                state
                    .scanned_bytes()
                    .max(lease_usage_before.scanned_bytes()),
                state
                    .decoded_records()
                    .max(lease_usage_before.decoded_records()),
                state.output_rows(),
                state.output_bytes(),
                state
                    .cpu_work_units()
                    .max(lease_usage_before.cpu_work_units()),
            );
            state.set_runtime_stats(
                state
                    .memory_peak_bytes()
                    .max(lease_usage_before.memory_peak_bytes()),
                state
                    .elapsed_seconds()
                    .max(lease_usage_before.wall_seconds()),
                state.reduced_pruning(),
                state.limiting_budget(),
            );
        }
        let historical_phase = matches!(start, TailStart::Historical { .. })
            || resume
                .as_ref()
                .is_some_and(|(state, _)| state.historical_markers().is_some());
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
                    .try_reserve_exact(bindings.len())
                    .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                for binding in &bindings {
                    positions.push(TailPosition::new(
                        binding.shard(),
                        match start {
                            TailStart::Now => binding.frontier(),
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
                state.set_progress(0, 0, 0, 0, query.cpu_work_units);
                if matches!(start, TailStart::Historical { .. }) {
                    let mut markers = Vec::new();
                    markers
                        .try_reserve_exact(bindings.len())
                        .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
                    for binding in &bindings {
                        markers.push(HistoricalMarker::new(
                            positron_domain::routing::CommitPosition::origin(),
                            binding.frontier(),
                        )?);
                    }
                    state.set_historical_markers(markers)?;
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
            memory_budget.execution_limit,
        )?;
        let phase = if historical_phase {
            TailPhase::HistoricalTemporalThenLiveCommitVector
        } else {
            TailPhase::LiveCommitVector
        };
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
        )?
        .with_tail_phase(phase);
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
            let bindings = state
                .source_bindings()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?;
            if bindings.len() != markers.len() {
                return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
            }
            let mut positions = Vec::new();
            positions
                .try_reserve_exact(markers.len())
                .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
            for (binding, marker) in bindings.iter().zip(markers) {
                positions.push(TailPosition::new(
                    binding.shard(),
                    marker.handoff_frontier(),
                ));
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
            lease_usage_before,
            lease_attempt,
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
            retained_memory_bytes: memory_budget.retained_bytes,
            runtime_memory_limit: memory_budget.execution_limit,
            cursor_observed: std::cell::Cell::new(false),
        };
        session.record_memory_peak(0)?;
        if matches!(start, TailStart::Historical { .. }) {
            session.fill_sources(max_rows)?;
        }
        Ok(session)
    }
}
