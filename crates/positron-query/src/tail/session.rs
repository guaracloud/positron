use crate::stream::QueryBatch;
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{TailCursor, TailCursorState, TailPosition};
use super::lease::TailLeaseOwner;
use super::source::TailSourceSet;
use super::terminal::{TailStats, TailTerminal, TerminalKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TailStart {
    Now,
    Historical { max_rows: usize },
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TailEvent {
    Header(crate::stream::QueryHeader),
    Batch(QueryBatch),
    Idle,
    Terminal(TailTerminal),
}

pub(super) struct PendingBatch {
    pub(super) positions: Vec<TailPosition>,
    pub(super) digest: [u8; 32],
    pub(super) rows: u64,
    pub(super) bytes: u64,
}

struct AdvancedBatch {
    state: TailCursorState,
    cursor: TailCursor,
    prior_digest: [u8; 32],
    next_sequence: u64,
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
    pub(super) pending_batch: Option<PendingBatch>,
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
    pub(super) memory_peak_bytes: u64,
    pub(super) elapsed_seconds: u64,
    pub(super) resume_count: u64,
    pub(super) repeated_batch_count: u64,
}

impl TailSession<'_, '_, '_, '_> {
    pub fn cursor(&self) -> &TailCursor {
        &self.cursor
    }

    pub fn acknowledge(&mut self, sequence: u64, digest: [u8; 32]) -> Result<(), QueryFailure> {
        let Some(pending) = self.pending_batch.as_ref() else {
            return (self.last_acknowledged == Some((sequence, digest)))
                .then_some(())
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::InvalidCursor));
        };
        if sequence != self.next_sequence || digest != pending.digest {
            return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
        }
        if self.buffer.is_empty() {
            return Err(super::internal());
        }
        let positions = pending.positions.clone();
        let rows = pending.rows;
        let bytes = pending.bytes;
        let output_rows = self.output_rows.checked_add(rows).ok_or_else(|| {
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::OutputRows)
        })?;
        let output_bytes = self.output_bytes.checked_add(bytes).ok_or_else(|| {
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::OutputBytes)
        })?;
        let advanced = self.candidate_advance(positions, digest, output_rows, output_bytes)?;
        self.state = advanced.state;
        self.cursor = advanced.cursor;
        self.prior_digest = advanced.prior_digest;
        self.next_sequence = advanced.next_sequence;
        self.output_rows = output_rows;
        self.output_bytes = output_bytes;
        if self.buffer.pop().is_none() {
            return Err(super::internal());
        }
        self.pending_batch = None;
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
                    self.terminal_stats(),
                ));
            }
            return self.take_terminal();
        }
        if self.terminal.is_some() {
            return self.take_terminal();
        }
        if let Some(batch) = self.buffer.front_cloned() {
            let (digest, sequence) = match self.pending_batch.as_ref() {
                Some(pending) => (pending.digest, self.next_sequence),
                None => {
                    self.terminal_after_progress_failure(TailTerminal::StoreUnavailable {
                        cursor: Some(self.cursor.clone()),
                        stats: self.terminal_stats(),
                    });
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
                    self.terminal_stats(),
                );
                self.terminal_after_progress_failure(terminal);
                self.take_terminal()
            },
        }
    }
    pub fn cancel(&mut self) {
        self.query.cancellation.cancel();
        self.finish(TerminalKind::Cancelled);
    }
    pub fn disconnect(&mut self) {
        self.finish(TerminalKind::Disconnected);
    }
    fn finish(&mut self, kind: TerminalKind) {
        if self.terminal.is_none() {
            self.buffer.clear();
            self.pending_batch = None;
            self.terminal = Some(kind.build(Some(self.cursor.clone()), self.terminal_stats()));
            self.replace_terminal_after_progress_failure();
        }
    }

    fn replace_terminal_after_progress_failure(&mut self) {
        if let Err(failure) = self.sync_progress() {
            self.terminal = Some(super::admission::terminal_for_failure(
                failure.code(),
                Some(self.cursor.clone()),
                self.terminal_stats(),
            ));
        }
    }

    pub(super) fn terminal_after_progress_failure(&mut self, terminal: TailTerminal) {
        self.terminal = Some(terminal);
        self.replace_terminal_after_progress_failure();
    }
    fn take_terminal(&mut self) -> Option<TailEvent> {
        let stats = self.terminal_stats();
        if let Some(terminal) = self.terminal.as_mut()
            && let Err(failure) = self.lease_owner.release()
        {
            *terminal = super::admission::terminal_for_failure(
                failure.code(),
                Some(self.cursor.clone()),
                stats,
            );
        }
        take_terminal_value(&mut self.terminal, &mut self.terminal_emitted)
    }
    fn candidate_advance(
        &self,
        positions: Vec<TailPosition>,
        digest: [u8; 32],
        output_rows: u64,
        output_bytes: u64,
    ) -> Result<AdvancedBatch, QueryFailure> {
        let mut state = self.state.clone();
        state.set_progress(
            self.scanned_bytes,
            self.decoded_records,
            output_rows,
            output_bytes,
            self.cpu_work_units,
        );
        let state = state.advance_batch(&positions, digest)?;
        let cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &state)?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(super::internal)?;
        Ok(AdvancedBatch {
            state,
            cursor,
            prior_digest: digest,
            next_sequence,
        })
    }

    pub(super) fn advance_positions(
        &mut self,
        positions: &[TailPosition],
    ) -> Result<(), QueryFailure> {
        self.sync_state_progress();
        let state = self.state.advance_positions(positions)?;
        let cursor = TailCursor::encode(&self.service.ledger.control_tokens(), &state)?;
        self.state = state;
        self.cursor = cursor;
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

    pub(super) fn terminal_stats(&self) -> TailStats {
        TailStats {
            scanned_bytes: self.scanned_bytes,
            decoded_records: self.decoded_records,
            emitted_records: self.output_rows,
            emitted_bytes: self.output_bytes,
            memory_peak_bytes: self.memory_peak_bytes,
            cpu_work_units: self.cpu_work_units,
            elapsed_seconds: self.elapsed_seconds,
            last_sequence: self.next_sequence.checked_sub(1),
            result_digest: self.prior_digest,
            cumulative_budget: self.query.budget,
            resume_count: self.resume_count,
            repeated_batch_count: self.repeated_batch_count,
            reduced_pruning: false,
        }
    }

    fn revalidate(&mut self) -> Result<(), QueryFailure> {
        if self.query.cancellation.is_cancelled() {
            self.finish(TerminalKind::Cancelled);
            return Ok(());
        }
        let now = self.service.now()?;
        self.elapsed_seconds = self
            .elapsed_seconds
            .max(now.saturating_sub(self.query.started_at));
        if now >= self.state.expiry() {
            self.finish(TerminalKind::Expired);
            return Ok(());
        }
        self.service
            .current_query_catalog(self.query.context)
            .map(|_| ())
            .inspect_err(|failure| {
                self.finish(if failure.code() == QueryFailureCode::Unauthorized {
                    TerminalKind::AuthorizationChanged
                } else {
                    TerminalKind::StoreUnavailable
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
    use super::{TailEvent, TailStats, TailTerminal, TerminalKind, take_terminal_value};
    use crate::{QueryBudget, QueryFailureCode};

    fn stats() -> TailStats {
        TailStats {
            scanned_bytes: 0,
            decoded_records: 0,
            emitted_records: 0,
            emitted_bytes: 0,
            memory_peak_bytes: 0,
            cpu_work_units: 0,
            elapsed_seconds: 0,
            last_sequence: None,
            result_digest: [0; 32],
            cumulative_budget: QueryBudget::new(1, 1, 1, 1, 1, 1).expect("test budget"),
            resume_count: 0,
            repeated_batch_count: 0,
            reduced_pruning: false,
        }
    }

    #[test]
    fn failure_terminals_and_terminal_emission_are_exhaustive() {
        assert!(matches!(
            super::super::admission::terminal_for_failure(
                QueryFailureCode::BudgetExhausted,
                None,
                stats()
            ),
            TailTerminal::BudgetExhausted { cursor: None, .. }
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(
                QueryFailureCode::Cancelled,
                None,
                stats()
            ),
            TailTerminal::Cancelled { cursor: None, .. }
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(
                QueryFailureCode::SnapshotExpired,
                None,
                stats()
            ),
            TailTerminal::Expired { cursor: None, .. }
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(
                QueryFailureCode::AuthorizationChanged,
                None,
                stats()
            ),
            TailTerminal::AuthorizationChanged { cursor: None, .. }
        ));
        assert!(matches!(
            super::super::admission::terminal_for_failure(
                QueryFailureCode::Internal,
                None,
                stats()
            ),
            TailTerminal::StoreUnavailable { cursor: None, .. }
        ));

        let mut terminal = Some(TailTerminal::Cancelled {
            cursor: None,
            stats: stats(),
        });
        let mut emitted = false;
        assert!(matches!(
            take_terminal_value(&mut terminal, &mut emitted),
            Some(TailEvent::Terminal(TailTerminal::Cancelled {
                cursor: None,
                ..
            }))
        ));
        assert!(emitted);
        assert!(take_terminal_value(&mut terminal, &mut emitted).is_none());
    }

    #[test]
    fn terminal_kind_builds_the_store_failure_variant() {
        assert!(matches!(
            TerminalKind::StoreUnavailable.build(None, stats()),
            TailTerminal::StoreUnavailable { cursor: None, .. }
        ));
    }
}
