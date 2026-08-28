use std::cell::Cell;

use crate::result_key::HistoricalTotalKey;
use crate::stream::QueryBatch;
use crate::{PlannedQuery, QueryFailure, QueryFailureCode, QueryService};

use super::buffer::TailBuffer;
use super::cursor::{TailCursor, TailCursorState, TailPosition};
use super::lease::{TailLeaseOwner, TailLeaseSet};
use super::source::TailSourceSet;
use super::terminal::{TailStats, TailTerminal, TerminalKind};
#[path = "session_leases.rs"]
mod leases;
#[path = "session_lifecycle.rs"]
mod lifecycle;
use leases::LeaseRotation;
#[path = "session_progress.rs"]
mod progress;
#[path = "session_usage.rs"]
mod usage;

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
    pub(super) historical_complete: bool,
    pub(super) historical_key: Option<HistoricalTotalKey>,
}

struct AdvancedBatch<'kernel, 'catalog, 'ledger> {
    state: TailCursorState,
    cursor: TailCursor,
    prior_digest: [u8; 32],
    next_sequence: u64,
    lease_rotation: LeaseRotation<'kernel, 'catalog, 'ledger>,
}

pub struct TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub(super) service: &'service QueryService<'kernel, 'catalog, 'ledger>,
    pub(super) query: PlannedQuery<'kernel>,
    pub(super) sources: TailSourceSet<'kernel, 'catalog, 'ledger>,
    pub(super) _lease: Option<positron_kernel::SnapshotLeaseGrant<'kernel>>,
    pub(super) lease_usage_before: positron_kernel::SnapshotLeaseUsage,
    pub(super) lease_attempt: Option<positron_kernel::SnapshotLeaseAttempt>,
    pub(super) lease_owner: TailLeaseOwner<'ledger, 'kernel, 'catalog>,
    pub(super) source_lease_owners: TailLeaseSet<'ledger, 'kernel, 'catalog>,
    pub(super) source_lease_grants: Vec<positron_kernel::SnapshotLeaseGrant<'kernel>>,
    pub(super) state: TailCursorState,
    pub(super) cursor: TailCursor,
    pub(super) delivery_cursor: Option<TailCursor>,
    pub(super) header: Option<crate::stream::QueryHeader>,
    pub(super) buffer: TailBuffer,
    pub(super) pending_batch: Option<PendingBatch>,
    pub(super) historical_frontiers: Vec<TailPosition>,
    pub(super) terminal: Option<TailTerminal>,
    pub(super) terminal_emitted: bool,
    pub(super) terminal_cursor_allowed: bool,
    pub(super) next_sequence: u64,
    pub(super) prior_digest: [u8; 32],
    pub(super) replay: bool,
    pub(super) replay_delivery: Option<(u64, [u8; 32])>,
    pub(super) last_acknowledged: Option<(u64, [u8; 32])>,
    pub(super) scanned_bytes: u64,
    pub(super) decoded_records: u64,
    pub(super) output_rows: u64,
    pub(super) output_bytes: u64,
    pub(super) cpu_work_units: u64,
    pub(super) memory_peak_bytes: u64,
    pub(super) retained_memory_bytes: u64,
    pub(super) runtime_memory_limit: u64,
    pub(super) elapsed_seconds: u64,
    pub(super) elapsed_anchor: u64,
    pub(super) reduced_pruning: bool,
    pub(super) limiting_budget: Option<crate::QueryBudgetDimension>,
    pub(super) resume_count: u64,
    pub(super) repeated_batch_count: u64,
    pub(super) cursor_observed: Cell<bool>,
}

impl<'service, 'kernel, 'catalog, 'ledger> TailSession<'service, 'kernel, 'catalog, 'ledger> {
    pub fn cursor(&self) -> &TailCursor {
        self.cursor_observed.set(true);
        self.delivery_cursor.as_ref().unwrap_or(&self.cursor)
    }

    pub fn safe_cursor(&self) -> &TailCursor {
        self.cursor_observed.set(true);
        &self.cursor
    }

    pub(super) fn publish_delivery_cursor(&mut self, digest: [u8; 32]) -> Result<(), QueryFailure> {
        if let Some(expected) = self.replay_delivery {
            if expected != (self.next_sequence, digest) {
                return Err(QueryFailure::new(QueryFailureCode::InvalidCursor));
            }
            self.replay_delivery = None;
            self.replay = false;
        }
        self.persist_lease_usage()?;
        let mut delivery_state = self.state.clone();
        delivery_state.set_unacknowledged_delivery((self.next_sequence, digest));
        self.delivery_cursor = Some(TailCursor::encode(
            &self.service.ledger.control_tokens(),
            &delivery_state,
        )?);
        Ok(())
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
        let historical_complete = pending.historical_complete;
        let historical_key = pending.historical_key;
        let output_rows = self.output_rows.checked_add(rows).ok_or_else(|| {
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::OutputRows)
        })?;
        let output_bytes = self.output_bytes.checked_add(bytes).ok_or_else(|| {
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::OutputBytes)
        })?;
        let advanced = match self.candidate_advance(
            positions,
            digest,
            output_rows,
            output_bytes,
            historical_complete,
            historical_key,
        ) {
            Ok(advanced) => advanced,
            Err(failure) => return Err(self.fail_acknowledgement(failure)),
        };
        let AdvancedBatch {
            state,
            cursor,
            prior_digest,
            next_sequence,
            lease_rotation,
        } = advanced;
        if let Err(failure) = self.commit_lease_rotation(lease_rotation) {
            return Err(self.fail_acknowledgement(failure));
        }
        self.state = state;
        self.cursor = cursor;
        self.delivery_cursor = None;
        self.prior_digest = prior_digest;
        self.next_sequence = next_sequence;
        self.output_rows = output_rows;
        self.output_bytes = output_bytes;
        if historical_complete {
            self.historical_frontiers.clear();
        }
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
            self.record_limiting_budget(&failure);
            if self.terminal.is_none() {
                self.terminal = Some(self.terminal_for_failure(&failure));
            }
            return self.take_terminal();
        }
        if self.terminal.is_some() {
            return self.take_terminal();
        }
        if let Some((records, claim)) = self.buffer.front_shared() {
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
            return Some(TailEvent::Batch(QueryBatch::from_shared(
                sequence,
                records,
                self.prior_digest,
                digest,
                claim,
            )));
        }
        if self.terminal.is_some() {
            return self.take_terminal();
        }
        match self.fill_sources(super::MAX_TAIL_BATCH_ROWS) {
            Ok(()) if self.terminal.is_some() => self.take_terminal(),
            Ok(()) if !self.buffer.is_empty() => self.poll(),
            Ok(()) => Some(TailEvent::Idle),
            Err(failure) => {
                self.record_limiting_budget(&failure);
                let terminal = self.terminal_for_failure(&failure);
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
            self.delivery_cursor = None;
            self.terminal = Some(kind.build(Some(self.cursor.clone()), self.terminal_stats()));
            self.replace_terminal_after_progress_failure();
        }
    }

    fn replace_terminal_after_progress_failure(&mut self) {
        if let Err(failure) = self.sync_progress() {
            self.terminal = Some(self.terminal_for_failure(&failure));
        }
    }

    fn fail_acknowledgement(&mut self, failure: QueryFailure) -> QueryFailure {
        self.delivery_cursor = None;
        self.record_limiting_budget(&failure);
        self.terminal = Some(self.terminal_for_failure(&failure));
        failure
    }

    pub(super) fn terminal_after_progress_failure(&mut self, terminal: TailTerminal) {
        self.terminal = Some(terminal);
        self.replace_terminal_after_progress_failure();
    }
    fn take_terminal(&mut self) -> Option<TailEvent> {
        if self.terminal.as_ref().is_some_and(TailTerminal::has_cursor) {
            // A caller that has taken the opaque cursor may reconnect after an
            // incomplete terminal. Keep the exact durable leases alive; their
            // bounded expiry and the kernel's cleanup path remain authoritative.
            if self._lease.as_ref().is_some_and(|lease| {
                self.state
                    .source_binding(lease.snapshot().scope().shard_id())
                    .is_some()
            }) {
                self.lease_owner.retain();
            }
            self.source_lease_owners.retain();
        } else {
            let primary_failure = self.lease_owner.release().err();
            let mut cleanup_failure = None;
            if let Some(failure) = primary_failure {
                crate::failure::retain_stronger(&mut cleanup_failure, failure);
            }
            if let Err(failure) = self.source_lease_owners.release() {
                crate::failure::retain_stronger(&mut cleanup_failure, failure);
            }
            if let Some(failure) = cleanup_failure {
                let selected = self.terminal.as_ref().map(|terminal| {
                    crate::failure::stronger_failure(
                        QueryFailure::new(terminal.failure_code()),
                        failure,
                    )
                });
                if let Some(selected) = selected {
                    self.terminal = Some(self.terminal_for_failure(&selected));
                }
            }
        }
        take_terminal_value(&mut self.terminal, &mut self.terminal_emitted)
    }
    fn terminal_for_failure(&self, failure: &QueryFailure) -> TailTerminal {
        super::admission::terminal_for_failure(
            failure.code(),
            self.terminal_cursor_allowed.then(|| self.cursor.clone()),
            self.terminal_stats(),
        )
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
            reduced_pruning: self.reduced_pruning,
            limiting_budget: self.limiting_budget,
        }
    }

    pub(super) fn record_memory_peak(&mut self, execution_peak: u64) -> Result<(), QueryFailure> {
        let total = self
            .retained_memory_bytes
            .checked_add(execution_peak)
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
        self.memory_peak_bytes = self.memory_peak_bytes.max(total);
        Ok(())
    }

    fn revalidate(&mut self) -> Result<(), QueryFailure> {
        if self.query.cancellation.is_cancelled() {
            self.finish(TerminalKind::Cancelled);
            return Ok(());
        }
        let now = self.service.now()?;
        let elapsed = now.saturating_sub(self.elapsed_anchor);
        self.elapsed_seconds = self.elapsed_seconds.checked_add(elapsed).ok_or_else(|| {
            QueryFailure::budget_exhausted(crate::QueryBudgetDimension::WallSeconds)
        })?;
        self.elapsed_anchor = now;
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
#[path = "session_tests.rs"]
mod tests;
