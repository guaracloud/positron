use std::collections::VecDeque;

use crate::stream::{QueryBatch, QueryHeader, ResultLease, ResultSnapshot};
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{TailCursor, TailCursorState, TailPosition, budget_digest};
use super::source::TailSourceSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailStart {
    Now,
    Historical { max_rows: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TailTerminal {
    ConsumerLagged(Option<TailCursor>),
    BudgetExhausted(Option<TailCursor>),
    Expired(Option<TailCursor>),
    AuthorizationChanged(Option<TailCursor>),
    Cancelled(Option<TailCursor>),
    Disconnected(Option<TailCursor>),
    StoreUnavailable(Option<TailCursor>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TailEvent {
    Header(QueryHeader),
    Batch(QueryBatch),
    Idle,
    Terminal(TailTerminal),
}

pub struct TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) service: &'service QueryService<'kernel, 'catalog, 'ledger>,
    pub(super) query: PlannedQuery<'kernel>,
    pub(super) sources: TailSourceSet<'kernel, 'catalog>,
    _lease: positron_kernel::SnapshotLeaseGrant<'kernel>,
    pub(super) state: TailCursorState,
    pub(super) cursor: TailCursor,
    pub(super) header: Option<QueryHeader>,
    pub(super) buffer: TailBuffer,
    pub(super) pending_batches: VecDeque<(Vec<TailPosition>, [u8; 32])>,
    pub(super) historical_frontiers: Vec<TailPosition>,
    pub(super) terminal: Option<TailTerminal>,
    pub(super) terminal_emitted: bool,
    pub(super) next_sequence: u64,
    pub(super) prior_digest: [u8; 32],
    pub(super) replay: bool,
    pub(super) scanned_bytes: u64,
    pub(super) decoded_records: u64,
    pub(super) output_rows: u64,
    pub(super) output_bytes: u64,
    pub(super) cpu_work_units: u64,
}

fn validate_resume_history(
    state: &TailCursorState,
    sources: &TailSourceSet<'_, '_>,
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
        if state.record_bound()
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

fn terminal_for_failure(code: QueryFailureCode, cursor: Option<TailCursor>) -> TailTerminal {
    match code {
        QueryFailureCode::BudgetExhausted => TailTerminal::BudgetExhausted(cursor),
        QueryFailureCode::Cancelled => TailTerminal::Cancelled(cursor),
        QueryFailureCode::SnapshotExpired => TailTerminal::Expired(cursor),
        QueryFailureCode::AuthorizationChanged => TailTerminal::AuthorizationChanged(cursor),
        _ => TailTerminal::StoreUnavailable(cursor),
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
        sources: TailSourceSet<'kernel, 'catalog>,
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
        sources: TailSourceSet<'kernel, 'catalog>,
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
        sources: TailSourceSet<'kernel, 'catalog>,
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
        if sources.tenant() != tenant {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
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
        let (state, cursor, replay) = match resume {
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
        let buffer = TailBuffer::new(maximum_records, query.budget.output_bytes())?;
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
        ) = (
            state.sequence(),
            state.prior_digest(),
            state.scanned_bytes(),
            state.decoded_records(),
            state.output_rows(),
            state.output_bytes(),
            state.cpu_work_units(),
        );
        let mut session = TailSession {
            service: self,
            query,
            sources,
            _lease: lease,
            state,
            cursor,
            header: Some(header),
            buffer,
            pending_batches: VecDeque::new(),
            historical_frontiers: if matches!(start, TailStart::Historical { .. }) {
                frontiers
                    .iter()
                    .map(|(shard, frontier)| TailPosition::new(*shard, *frontier))
                    .collect()
            } else {
                Vec::new()
            },
            terminal: None,
            terminal_emitted: false,
            next_sequence,
            prior_digest,
            replay,
            scanned_bytes,
            decoded_records,
            output_rows,
            output_bytes,
            cpu_work_units,
        };
        if matches!(start, TailStart::Historical { .. }) {
            session.fill_sources(max_rows)?;
        }
        Ok(session)
    }
}

impl TailSession<'_, '_, '_, '_> {
    pub fn cursor(&self) -> &TailCursor {
        &self.cursor
    }
    pub fn poll(&mut self) -> Option<TailEvent> {
        if self.terminal_emitted {
            return None;
        }
        if let Some(header) = self.header.take() {
            return Some(TailEvent::Header(header));
        }
        if self.revalidate().is_err() || self.terminal.is_some() {
            return self.take_terminal();
        }
        if let Some(batch) = self.buffer.pop() {
            let (positions, digest) = match self.pending_batches.pop_front() {
                Some(pending) => pending,
                None => {
                    let _ = self.sync_progress();
                    self.terminal = Some(TailTerminal::StoreUnavailable(Some(self.cursor.clone())));
                    return self.take_terminal();
                },
            };
            let prior = self.prior_digest;
            if self.advance(positions, digest).is_err() {
                let _ = self.sync_progress();
                self.terminal = Some(TailTerminal::StoreUnavailable(Some(self.cursor.clone())));
                return self.take_terminal();
            }
            let sequence = self.next_sequence.saturating_sub(1);
            return Some(TailEvent::Batch(QueryBatch::new(
                sequence, batch, prior, digest,
            )));
        }
        if let Some(terminal) = self.terminal.take() {
            self.terminal_emitted = true;
            return Some(TailEvent::Terminal(terminal));
        }
        match self.fill_sources(super::MAX_TAIL_BATCH_ROWS) {
            Ok(()) if !self.buffer.is_empty() => self.poll(),
            Ok(()) => Some(TailEvent::Idle),
            Err(failure) => {
                let _ = self.sync_progress();
                self.terminal = Some(terminal_for_failure(
                    failure.code(),
                    Some(self.cursor.clone()),
                ));
                self.take_terminal()
            },
        }
    }
    pub fn cancel(&mut self) {
        self.query.cancellation.cancel();
        self.finish(TailTerminal::Cancelled);
    }
    pub fn disconnect(&mut self) {
        self.finish(TailTerminal::Disconnected);
    }
    fn finish(&mut self, kind: fn(Option<TailCursor>) -> TailTerminal) {
        if self.terminal.is_none() {
            let _ = self.sync_progress();
            self.buffer.clear();
            self.pending_batches.clear();
            self.terminal = Some(kind(Some(self.cursor.clone())));
        }
    }
    fn take_terminal(&mut self) -> Option<TailEvent> {
        take_terminal_value(&mut self.terminal, &mut self.terminal_emitted)
    }
    fn advance(
        &mut self,
        positions: Vec<TailPosition>,
        digest: [u8; 32],
    ) -> Result<(), QueryFailure> {
        self.sync_state_progress();
        self.state = self.state.advance_batch(&positions, digest)?;
        self.cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &self.state)?;
        self.prior_digest = digest;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(super::internal)?;
        Ok(())
    }

    pub(super) fn advance_positions(
        &mut self,
        positions: &[TailPosition],
    ) -> Result<(), QueryFailure> {
        self.sync_state_progress();
        self.state = self.state.advance_positions(positions)?;
        self.cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &self.state)?;
        Ok(())
    }
    pub(super) fn sync_progress(&mut self) -> Result<(), QueryFailure> {
        self.sync_state_progress();
        self.cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &self.state)?;
        Ok(())
    }
    fn sync_state_progress(&mut self) {
        self.state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            self.output_rows,
            self.output_bytes,
            self.cpu_work_units,
        );
    }
    fn revalidate(&mut self) -> Result<(), QueryFailure> {
        if self.query.cancellation.is_cancelled() {
            self.finish(TailTerminal::Cancelled);
            return Ok(());
        }
        let now = self.service.now()?;
        if now >= self.state.expiry() {
            self.finish(TailTerminal::Expired);
            return Ok(());
        }
        self.service
            .current_query_catalog(self.query.context)
            .map(|_| ())
            .inspect_err(|failure| {
                self.finish(if failure.code() == QueryFailureCode::Unauthorized {
                    TailTerminal::AuthorizationChanged
                } else {
                    TailTerminal::StoreUnavailable
                });
            })
    }
}

fn take_terminal_value(
    terminal: &mut Option<TailTerminal>,
    terminal_emitted: &mut bool,
) -> Option<TailEvent> {
    terminal.take().map(|terminal| {
        *terminal_emitted = true;
        TailEvent::Terminal(terminal)
    })
}

#[cfg(test)]
mod tests {
    use super::{TailEvent, TailTerminal, take_terminal_value, terminal_for_failure};
    use crate::QueryFailureCode;

    #[test]
    fn failure_terminals_and_terminal_emission_are_exhaustive() {
        assert!(matches!(
            terminal_for_failure(QueryFailureCode::BudgetExhausted, None),
            TailTerminal::BudgetExhausted(None)
        ));
        assert!(matches!(
            terminal_for_failure(QueryFailureCode::Cancelled, None),
            TailTerminal::Cancelled(None)
        ));
        assert!(matches!(
            terminal_for_failure(QueryFailureCode::SnapshotExpired, None),
            TailTerminal::Expired(None)
        ));
        assert!(matches!(
            terminal_for_failure(QueryFailureCode::AuthorizationChanged, None),
            TailTerminal::AuthorizationChanged(None)
        ));
        assert!(matches!(
            terminal_for_failure(QueryFailureCode::Internal, None),
            TailTerminal::StoreUnavailable(None)
        ));

        let mut terminal = Some(TailTerminal::Cancelled(None));
        let mut emitted = false;
        assert!(matches!(
            take_terminal_value(&mut terminal, &mut emitted),
            Some(TailEvent::Terminal(TailTerminal::Cancelled(None)))
        ));
        assert!(emitted);
        assert!(take_terminal_value(&mut terminal, &mut emitted).is_none());
    }
}
