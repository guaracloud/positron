use std::collections::VecDeque;

use crate::stream::QueryBatch;
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{TailCursor, TailCursorState, TailPosition};
use super::lease::TailLeaseOwner;
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
    Header(crate::stream::QueryHeader),
    Batch(QueryBatch),
    Idle,
    Terminal(TailTerminal),
}

pub struct TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) service: &'service QueryService<'kernel, 'catalog, 'ledger>,
    pub(super) query: PlannedQuery<'kernel>,
    pub(super) sources: TailSourceSet<'kernel, 'catalog>,
    pub(super) _lease: positron_kernel::SnapshotLeaseGrant<'kernel>,
    pub(super) lease_owner: TailLeaseOwner<'ledger, 'kernel, 'catalog>,
    pub(super) state: TailCursorState,
    pub(super) cursor: TailCursor,
    pub(super) header: Option<crate::stream::QueryHeader>,
    pub(super) buffer: TailBuffer,
    pub(super) pending_batches: VecDeque<(Vec<TailPosition>, [u8; 32])>,
    pub(super) historical_frontiers: Vec<TailPosition>,
    pub(super) terminal: Option<TailTerminal>,
    pub(super) terminal_emitted: bool,
    pub(super) next_sequence: u64,
    pub(super) prior_digest: [u8; 32],
    pub(super) replay: bool,
    pub(super) last_acknowledged: Option<(u64, [u8; 32])>,
    pub(super) scanned_bytes: u64,
    pub(super) decoded_records: u64,
    pub(super) output_rows: u64,
    pub(super) output_bytes: u64,
    pub(super) cpu_work_units: u64,
}

impl TailSession<'_, '_, '_, '_> {
    pub fn cursor(&self) -> &TailCursor {
        &self.cursor
    }

    pub fn acknowledge(&mut self, sequence: u64, digest: [u8; 32]) -> Result<(), QueryFailure> {
        let Some((positions, expected_digest)) = self.pending_batches.front().cloned() else {
            return (self.last_acknowledged == Some((sequence, digest)))
                .then_some(())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor));
        };
        if sequence != self.next_sequence || digest != expected_digest {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        if self.buffer.pop().is_none() {
            return Err(super::internal());
        }
        self.pending_batches.pop_front();
        self.advance(positions, digest)?;
        self.last_acknowledged = Some((sequence, digest));
        Ok(())
    }

    pub fn poll(&mut self) -> Option<TailEvent> {
        if self.terminal_emitted {
            return None;
        }
        if let Some(header) = self.header.take() {
            return Some(TailEvent::Header(header));
        }
        if let Err(failure) = self.revalidate() {
            if self.terminal.is_none() {
                self.terminal = Some(super::admission::terminal_for_failure(
                    failure.code(),
                    Some(self.cursor.clone()),
                ));
            }
            return self.take_terminal();
        }
        if self.terminal.is_some() {
            return self.take_terminal();
        }
        if let Some(batch) = self.buffer.front_cloned() {
            let (digest, sequence) = match self.pending_batches.front() {
                Some((_, digest)) => (*digest, self.next_sequence),
                None => {
                    self.terminal_after_progress_failure(TailTerminal::StoreUnavailable(Some(
                        self.cursor.clone(),
                    )));
                    return self.take_terminal();
                },
            };
            return Some(TailEvent::Batch(QueryBatch::new(
                sequence,
                batch,
                self.prior_digest,
                digest,
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
                let terminal = super::admission::terminal_for_failure(
                    failure.code(),
                    Some(self.cursor.clone()),
                );
                self.terminal_after_progress_failure(terminal);
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
            self.buffer.clear();
            self.pending_batches.clear();
            self.terminal = Some(kind(Some(self.cursor.clone())));
            self.replace_terminal_after_progress_failure();
        }
    }

    fn replace_terminal_after_progress_failure(&mut self) {
        if let Err(failure) = self.sync_progress() {
            self.terminal = Some(super::admission::terminal_for_failure(
                failure.code(),
                Some(self.cursor.clone()),
            ));
        }
    }

    pub(super) fn terminal_after_progress_failure(&mut self, terminal: TailTerminal) {
        self.terminal = Some(terminal);
        self.replace_terminal_after_progress_failure();
    }
    fn take_terminal(&mut self) -> Option<TailEvent> {
        if let Some(terminal) = self.terminal.as_mut()
            && let Err(failure) = self.lease_owner.release()
        {
            *terminal =
                super::admission::terminal_for_failure(failure.code(), Some(self.cursor.clone()));
        }
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
    use super::{TailEvent, TailTerminal, take_terminal_value};
    use crate::QueryFailureCode;

    #[test]
    fn failure_terminals_and_terminal_emission_are_exhaustive() {
        assert!(matches!(
            super::super::admission::terminal_for_failure(QueryFailureCode::BudgetExhausted, None),
            TailTerminal::BudgetExhausted(None)
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(QueryFailureCode::Cancelled, None),
            TailTerminal::Cancelled(None)
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(QueryFailureCode::SnapshotExpired, None),
            TailTerminal::Expired(None)
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(
                QueryFailureCode::AuthorizationChanged,
                None
            ),
            TailTerminal::AuthorizationChanged(None)
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(QueryFailureCode::Internal, None),
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
