use crate::stream::{QueryHeader, ResultLease, ResultSnapshot};
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{HistoricalMarker, TailCursor, TailCursorState, TailPosition, budget_digest};
use super::lease::{TailLeaseOwner, TailLeaseSet};
use super::session::{TailSession, TailStart};
use super::source::TailSourceSet;
use super::terminal::{TailStats, TailTerminal};

fn validate_resume_history(
    state: &TailCursorState,
    sources: &TailSourceSet<'_, '_, '_>,
) -> Result<(), QueryFailure> {
    for reader in sources.readers() {
        let snapshot = reader
            .snapshot()
            .map_err(crate::execution_support::map_ledger_failure)?;
        let Some(position) = state
            .positions()
            .iter()
            .find(|position| position.shard() == snapshot.scope().shard_id())
        else {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        };
        if position.position() > snapshot.frontier() {
            return Err(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        }
        if let Some(markers) = state.historical_markers() {
            let marker = markers
                .get(
                    state
                        .positions()
                        .iter()
                        .position(|candidate| candidate.shard() == snapshot.scope().shard_id())
                        .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor))?,
                )
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

pub(super) fn terminal_for_failure(
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

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn tail(
        &self,
        query: PlannedQuery<'kernel>,
        start: TailStart,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.tail_with_sources(query, start, TailSourceSet::single(reader)?)
    }

    pub fn tail_with_sources(
        &self,
        query: PlannedQuery<'kernel>,
        start: TailStart,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        self.admit_tail(query, start, None, sources)
    }

    pub fn resume_tail(
        &self,
        query: PlannedQuery<'kernel>,
        cursor: &TailCursor,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        self.resume_tail_with_sources(query, cursor, TailSourceSet::single(reader)?)
    }

    pub fn resume_tail_with_sources(
        &self,
        query: PlannedQuery<'kernel>,
        cursor: &TailCursor,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let state = TailCursor::decode(&self.ledger.control_tokens(), cursor)?;
        let (tenant, _, _generation) = self.current_query_catalog(query.context)?;
        let signal_digest = sources.digest(&self.ledger.control_tokens())?;
        state.validate_for_resume(
            query.context.principal_id(),
            tenant,
            query.context.authorization_generation(),
            query.plan_digest,
            signal_digest,
            self.now()?,
        )?;
        validate_resume_history(&state, &sources)?;
        self.admit_tail(
            query,
            TailStart::Now,
            Some((state, cursor.clone())),
            sources,
        )
    }

    fn admit_tail(
        &self,
        query: PlannedQuery<'kernel>,
        start: TailStart,
        resume: Option<(TailCursorState, TailCursor)>,
        sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let (tenant, catalog_identity, generation) = self.current_query_catalog(query.context)?;
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
        }
        if query.plan.tail_incompatible() {
            return Err(QueryFailure::new(QueryFailureCode::UnsupportedQuery));
        }
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
        let lease = self
            .ledger
            .create_snapshot_lease(now, expiry)
            .map_err(crate::execution_support::map_ledger_failure)?;
        let lease_owner = TailLeaseOwner::new(self.ledger, lease.identity());
        if sources.tenant() != tenant {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let mut source_lease_owners = TailLeaseSet::with_capacity(sources.readers().len())?;
        for reader in sources.readers() {
            if reader.scope() == self.ledger.scope() {
                continue;
            }
            let authority = reader
                .lease_authority()
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::StoreUnavailable))?;
            let source_lease = authority
                .create_snapshot_lease(now, expiry)
                .map_err(crate::execution_support::map_ledger_failure)?;
            source_lease_owners.push(TailLeaseOwner::new(authority, source_lease.identity()));
            drop(source_lease);
        }
        let mut frontiers = Vec::new();
        frontiers
            .try_reserve_exact(sources.readers().len())
            .map_err(|_| QueryFailure::new(QueryFailureCode::ResourceExhausted))?;
        let mut header_snapshot = None;
        for reader in sources.readers() {
            let snapshot = reader
                .snapshot()
                .map_err(crate::execution_support::map_ledger_failure)?;
            if snapshot.scope().tenant_id() != tenant {
                return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
            }
            if header_snapshot.is_none() {
                header_snapshot = Some(snapshot);
            } else {
                frontiers.push((snapshot.scope().shard_id(), snapshot.frontier()));
            }
        }
        let snapshot = header_snapshot.ok_or_else(super::internal)?;
        frontiers.push((snapshot.scope().shard_id(), snapshot.frontier()));
        frontiers.sort_unstable_by_key(|(shard, _)| *shard);
        let digest = sources.digest(&self.ledger.control_tokens())?;
        let expected_budget = budget_digest(&self.ledger.control_tokens(), query.budget)?;
        let resumed = resume.is_some();
        let (mut state, cursor, replay) = match resume {
            Some((state, cursor)) => {
                if state.positions().len() != sources.readers().len()
                    || state
                        .positions()
                        .iter()
                        .any(|position| !sources.contains(position.shard()))
                {
                    return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
                }
                let replay = !state.record_bound()
                    && state.sequence() == 0
                    && state.prior_digest() == [0; 32];
                state.validate_budget(expected_budget)?;
                (state, cursor, replay)
            },
            None => {
                let positions = frontiers
                    .iter()
                    .map(|(shard, frontier)| {
                        TailPosition::new(
                            *shard,
                            match start {
                                TailStart::Now => *frontier,
                                TailStart::Historical { .. } => {
                                    positron_domain::routing::CommitPosition::origin()
                                },
                            },
                        )
                    })
                    .collect();
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
                let cursor = TailCursor::encode(&self.ledger.control_tokens(), &state)?;
                (state, cursor, false)
            },
        };
        let max_rows = match start {
            TailStart::Historical { max_rows } => max_rows,
            TailStart::Now => 1,
        };
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
        let historical_frontiers = state
            .historical_markers()
            .map(|markers| {
                frontiers
                    .iter()
                    .zip(markers.iter())
                    .map(|((shard, _), marker)| {
                        TailPosition::new(*shard, marker.handoff_frontier())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let elapsed_anchor = query.last_observed_at;
        let mut session = TailSession {
            service: self,
            query,
            sources,
            _lease: lease,
            lease_owner,
            source_lease_owners,
            state,
            cursor,
            header: Some(header),
            buffer,
            pending_batch: None,
            historical_frontiers,
            terminal: None,
            terminal_emitted: false,
            next_sequence,
            prior_digest,
            replay,
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
        };
        if matches!(start, TailStart::Historical { .. }) {
            session.fill_sources(max_rows)?;
        }
        Ok(session)
    }
}
