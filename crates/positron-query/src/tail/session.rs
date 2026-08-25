use std::collections::VecDeque;

use crate::stream::{QueryBatch, QueryHeader, ResultLease, ResultSnapshot};
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{TailCursor, TailCursorState, TailPosition};
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
        let signal_digest = sources.digest();
        state.validate_for_resume(
            query.context.principal_id(),
            tenant,
            query.context.authorization_generation(),
            query.plan_digest,
            signal_digest,
            self.now()?,
        )?;
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
        let expiry = query
            .started_at
            .checked_add(query.budget.wall_seconds())
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidBudget))?;
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
        let digest = sources.digest();
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
                (state, cursor, true)
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
                let state = TailCursorState::new(
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
            terminal: None,
            terminal_emitted: false,
            next_sequence: 0,
            prior_digest: [0; 32],
            replay,
            scanned_bytes: 0,
            decoded_records: 0,
            output_rows: 0,
            output_bytes: 0,
            cpu_work_units: 0,
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
        if let Some(batch) = self.buffer.pop() {
            let (positions, digest) = match self.pending_batches.pop_front() {
                Some(pending) => pending,
                None => {
                    self.terminal = Some(TailTerminal::StoreUnavailable(Some(self.cursor.clone())));
                    return self.take_terminal();
                },
            };
            let prior = self.prior_digest;
            if self.advance(positions, digest).is_err() {
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
        if self.revalidate().is_err() {
            return self.take_terminal();
        }
        match self.fill_sources(super::MAX_TAIL_BATCH_ROWS) {
            Ok(()) if !self.buffer.is_empty() => self.poll(),
            Ok(()) => Some(TailEvent::Idle),
            Err(failure) => {
                self.terminal = Some(match failure.code() {
                    QueryFailureCode::BudgetExhausted => {
                        TailTerminal::BudgetExhausted(Some(self.cursor.clone()))
                    },
                    QueryFailureCode::Cancelled => {
                        TailTerminal::Cancelled(Some(self.cursor.clone()))
                    },
                    _ => TailTerminal::StoreUnavailable(Some(self.cursor.clone())),
                });
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
            self.terminal = Some(kind(Some(self.cursor.clone())));
        }
    }
    fn take_terminal(&mut self) -> Option<TailEvent> {
        self.terminal.take().map(|terminal| {
            self.terminal_emitted = true;
            TailEvent::Terminal(terminal)
        })
    }
    fn advance(
        &mut self,
        positions: Vec<TailPosition>,
        digest: [u8; 32],
    ) -> Result<(), QueryFailure> {
        self.state = self.state.advance_batch(&positions, digest)?;
        self.cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &self.state)?;
        self.prior_digest = digest;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(super::internal)?;
        Ok(())
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
