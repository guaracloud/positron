use std::collections::VecDeque;

use positron_domain::routing::VirtualShardId;
use positron_kernel::CommittedLedgerReader;

use crate::stream::{QueryBatch, QueryHeader, QueryRecord, ResultLease, ResultSnapshot};
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{TailCursor, TailCursorState, TailPosition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailStart {
    Now,
    Historical { max_rows: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TailTerminal {
    ConsumerLagged(Option<TailCursor>),
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
    pub(super) reader: CommittedLedgerReader<'kernel, 'catalog>,
    state: TailCursorState,
    cursor: TailCursor,
    header: Option<QueryHeader>,
    buffer: TailBuffer,
    pending_positions: VecDeque<TailPosition>,
    terminal: Option<TailTerminal>,
    terminal_emitted: bool,
    next_sequence: u64,
    prior_digest: [u8; 32],
    shard: VirtualShardId,
}

impl<'kernel, 'catalog, 'ledger> QueryService<'kernel, 'catalog, 'ledger> {
    pub fn tail(
        &self,
        query: PlannedQuery<'kernel>,
        start: TailStart,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        self.admit_tail(query, start, None)
    }

    pub fn resume_tail(
        &self,
        query: PlannedQuery<'kernel>,
        cursor: &TailCursor,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let state = TailCursor::decode(&self.ledger.control_tokens(), cursor)?;
        let (tenant, _, _generation) = self.current_query_catalog(query.context)?;
        let signal_digest = signal_digest(self.ledger.scope());
        state.validate_for_resume(
            query.context.principal_id(),
            tenant,
            query.context.authorization_generation(),
            query.plan_digest,
            signal_digest,
            self.now()?,
        )?;
        if state.positions().len() != 1 {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        self.admit_tail(query, TailStart::Now, Some((state, cursor.clone())))
    }

    fn admit_tail(
        &self,
        query: PlannedQuery<'kernel>,
        start: TailStart,
        resume: Option<(TailCursorState, TailCursor)>,
    ) -> Result<TailSession<'_, 'kernel, 'catalog, 'ledger>, QueryFailure> {
        let (tenant, catalog_identity, generation) = self.current_query_catalog(query.context)?;
        if query.cancellation.is_cancelled() {
            return Err(QueryFailure::new(QueryFailureCode::Cancelled));
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
        let reader = self
            .ledger
            .reader()
            .map_err(crate::execution_support::map_ledger_failure)?;
        let snapshot = reader
            .snapshot()
            .map_err(crate::execution_support::map_ledger_failure)?;
        let shard = snapshot.scope().shard_id();
        if snapshot.scope().tenant_id() != tenant {
            return Err(QueryFailure::new(QueryFailureCode::Unauthorized));
        }
        let digest = signal_digest(snapshot.scope());
        let (state, cursor, initial_frontier) = match resume {
            Some((state, cursor)) => {
                let frontier = state.positions()[0].position();
                (state, cursor, frontier)
            },
            None => {
                let frontier = match start {
                    TailStart::Now => snapshot.frontier(),
                    TailStart::Historical { .. } => {
                        positron_domain::routing::CommitPosition::origin()
                    },
                };
                let state = TailCursorState::new(
                    query.context.principal_id(),
                    tenant,
                    query.context.authorization_generation(),
                    query.plan_digest,
                    digest,
                    vec![TailPosition::new(shard, frontier)],
                    expiry,
                    0,
                    [0; 32],
                )?;
                let cursor = TailCursor::encode(&self.ledger.control_tokens(), &state)?;
                (state, cursor, frontier)
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
            ResultLease::new([0; 16], expiry),
            None,
        )?;
        let mut session = TailSession {
            service: self,
            query,
            reader,
            state,
            cursor,
            header: Some(header),
            buffer,
            pending_positions: VecDeque::new(),
            terminal: None,
            terminal_emitted: false,
            next_sequence: 0,
            prior_digest: [0; 32],
            shard,
        };
        if matches!(start, TailStart::Historical { .. }) {
            session.fill_snapshot(&snapshot, initial_frontier, max_rows)?;
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
            if let Some(position) = self.pending_positions.pop_front() {
                let _ = self.advance(position);
            }
            let sequence = if self.next_sequence == 0 {
                0
            } else {
                self.next_sequence - 1
            };
            return Some(TailEvent::Batch(QueryBatch::new(
                sequence,
                batch,
                self.prior_digest,
                self.prior_digest,
            )));
        }
        if let Some(terminal) = self.terminal.take() {
            self.terminal_emitted = true;
            return Some(TailEvent::Terminal(terminal));
        }
        if self.revalidate().is_err() {
            return self.take_terminal();
        }
        match self.reader.snapshot() {
            Ok(snapshot) => {
                let after = self
                    .state
                    .positions()
                    .first()
                    .map_or(positron_domain::routing::CommitPosition::origin(), |p| {
                        p.position()
                    });
                if self
                    .fill_snapshot(&snapshot, after, super::MAX_TAIL_BATCH_ROWS)
                    .is_ok()
                    && !self.buffer.is_empty()
                {
                    self.poll()
                } else {
                    Some(TailEvent::Idle)
                }
            },
            Err(_) => {
                self.terminal = Some(TailTerminal::StoreUnavailable(Some(self.cursor.clone())));
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
    fn fill_snapshot(
        &mut self,
        snapshot: &positron_kernel::LedgerSnapshot<'_>,
        after: positron_domain::routing::CommitPosition,
        limit: usize,
    ) -> Result<(), QueryFailure> {
        let mut records = Vec::new();
        let mut last = None;
        for block in snapshot.blocks() {
            if block.position() <= after || records.len() >= limit {
                continue;
            }
            records.push(QueryRecord::count_record(1));
            last = Some(TailPosition::new(self.shard, block.position()));
        }
        if records.is_empty() {
            return Ok(());
        }
        let position = last.ok_or_else(super::internal)?;
        if self.buffer.push(records).is_err() {
            self.terminal = Some(TailTerminal::ConsumerLagged(Some(self.cursor.clone())));
            return Ok(());
        }
        self.pending_positions.push_back(position);
        Ok(())
    }
    fn advance(&mut self, position: TailPosition) -> Result<(), QueryFailure> {
        let digest = self.prior_digest;
        self.state =
            self.state
                .advance(self.shard, position.position(), position.ordinal(), digest)?;
        self.cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &self.state)?;
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

fn signal_digest(scope: positron_kernel::SegmentScope) -> [u8; 32] {
    let mut digest = [0; 32];
    digest[0] = match scope.signal_kind() {
        positron_domain::routing::SignalKind::Logs => 1,
        positron_domain::routing::SignalKind::Traces => 2,
    };
    digest[1..5].copy_from_slice(&scope.shard_id().value().to_be_bytes());
    digest
}
