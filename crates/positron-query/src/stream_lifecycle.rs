use crate::{
    QueryEvent, QueryFailure, QueryFailureCode, QueryIncomplete, QueryStats, QueryTerminal,
};
use positron_kernel::TransferredResourceReservation;

type LeaseRelease<'lease> = Box<dyn FnMut() -> Result<(), QueryFailure> + 'lease>;

pub struct QueryStream<'lease> {
    events: std::vec::IntoIter<QueryEvent>,
    terminal_observed: bool,
    releasing_terminal_observed: bool,
    release: Option<LeaseRelease<'lease>>,
    retain_for_resume: bool,
    resumable_delivery_observed: bool,
    observed_stats: QueryStats,
    batch_stats: QueryStats,
    cancellation: crate::QueryCancellation,
    cancellation_transitioned: bool,
    admission: Option<TransferredResourceReservation>,
}

impl std::fmt::Debug for QueryStream<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueryStream { <bounded-events> }")
    }
}

impl<'lease> QueryStream<'lease> {
    pub(crate) fn new(
        events: Vec<QueryEvent>,
        release: Option<LeaseRelease<'lease>>,
        retain_for_resume: bool,
        observed_stats: QueryStats,
        batch_stats: QueryStats,
        cancellation: crate::QueryCancellation,
        admission: Option<TransferredResourceReservation>,
    ) -> Self {
        Self {
            events: events.into_iter(),
            terminal_observed: false,
            releasing_terminal_observed: false,
            release,
            retain_for_resume,
            resumable_delivery_observed: false,
            observed_stats,
            batch_stats,
            cancellation,
            cancellation_transitioned: false,
            admission,
        }
    }

    pub(crate) fn new_releasing(
        mut events: Vec<QueryEvent>,
        mut release: LeaseRelease<'lease>,
        retain_for_resume: bool,
        observed_stats: QueryStats,
        batch_stats: QueryStats,
        cancellation: crate::QueryCancellation,
        admission: Option<TransferredResourceReservation>,
    ) -> Self {
        let release = if retain_for_resume {
            Some(release)
        } else {
            match release() {
                Ok(()) => None,
                Err(failure) => {
                    events.retain(|event| !matches!(event, QueryEvent::Terminal(_)));
                    events.push(QueryEvent::Terminal(QueryTerminal::Incomplete(
                        QueryIncomplete::new(failure, batch_stats),
                    )));
                    Some(release)
                },
            }
        };
        Self::new(
            events,
            release,
            retain_for_resume,
            observed_stats,
            batch_stats,
            cancellation,
            admission,
        )
    }

    pub fn cancel(&mut self) -> Result<(), QueryFailure> {
        self.cancellation.cancel();
        self.begin_cancellation();
        match self.release_lease() {
            Ok(()) => Ok(()),
            Err(failure) => {
                self.replace_pending_with_failure(failure.clone());
                Err(failure)
            },
        }
    }

    fn begin_cancellation(&mut self) {
        if self.cancellation_transitioned {
            return;
        }
        self.cancellation_transitioned = true;
        self.replace_pending_with_failure(QueryFailure::new(QueryFailureCode::Cancelled));
    }

    fn replace_pending_with_failure(&mut self, failure: QueryFailure) {
        if self.terminal_observed {
            self.events = Vec::new().into_iter();
        } else {
            let pending_header =
                if matches!(self.events.as_slice().first(), Some(QueryEvent::Header(_))) {
                    self.events.next()
                } else {
                    None
                };
            let mut events = Vec::with_capacity(usize::from(pending_header.is_some()) + 1);
            events.extend(pending_header);
            events.push(QueryEvent::Terminal(QueryTerminal::Incomplete(
                QueryIncomplete::new(failure, self.observed_stats),
            )));
            self.events = events.into_iter();
        }
    }

    fn release_lease(&mut self) -> Result<(), QueryFailure> {
        let Some(release) = self.release.as_mut() else {
            return Ok(());
        };
        release()?;
        self.release = None;
        Ok(())
    }
}

impl Iterator for QueryStream<'_> {
    type Item = QueryEvent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cancellation.is_cancelled()
            && !self.cancellation_transitioned
            && !self.terminal_observed
        {
            self.begin_cancellation();
            if let Err(failure) = self.release_lease() {
                self.replace_pending_with_failure(failure);
            }
        }
        let event = self.events.next();
        if matches!(
            event.as_ref(),
            Some(QueryEvent::Header(header)) if header.initial_cursor().is_some()
        ) || matches!(
            event.as_ref(),
            Some(QueryEvent::Terminal(QueryTerminal::Continued(_)))
        ) {
            self.resumable_delivery_observed = true;
        }
        if matches!(event, Some(QueryEvent::Batch(_))) {
            self.observed_stats = self.batch_stats;
        }
        if matches!(
            event,
            Some(QueryEvent::Terminal(
                QueryTerminal::Complete(_) | QueryTerminal::Incomplete(_)
            ))
        ) {
            self.releasing_terminal_observed = true;
        }
        if matches!(event, Some(QueryEvent::Terminal(_))) {
            self.terminal_observed = true;
            self.admission = None;
        }
        event
    }
}

impl Drop for QueryStream<'_> {
    fn drop(&mut self) {
        if !self.terminal_observed {
            self.cancellation.cancel();
        }
        if !(self.retain_for_resume
            && self.resumable_delivery_observed
            && !self.releasing_terminal_observed)
            && let Some(release) = self.release.as_mut()
        {
            match release() {
                Ok(()) | Err(_) => {},
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::QueryStream;
    use crate::stream::QueryCounters;
    use crate::{
        LogicalPlan, QueryBudget, QueryEvent, QueryFailure, QueryFailureCode, QueryHeader,
        QueryStats, QueryTerminal, ResultLease, ResultSnapshot, TemporalAxis, TemporalRange,
    };

    #[test]
    fn initial_release_failure_keeps_header_and_frames_one_retryable_terminal() {
        let release_attempts = Arc::new(AtomicU64::new(0));
        let attempts = Arc::clone(&release_attempts);
        let release = Box::new(move || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(QueryFailure::new(QueryFailureCode::StoreUnavailable))
            } else {
                Ok(())
            }
        });
        let stats = empty_stats();
        let mut stream = QueryStream::new_releasing(
            vec![
                QueryEvent::Header(test_header()),
                QueryEvent::Terminal(QueryTerminal::Complete(stats)),
            ],
            release,
            false,
            stats,
            stats,
            crate::QueryCancellation::new(),
            None,
        );

        assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));
        assert!(matches!(
            stream.next(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::StoreUnavailable
                    && incomplete.stats() == stats
        ));
        assert!(stream.next().is_none());
        drop(stream);
        assert_eq!(release_attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cancellation_replaces_complete_truth_even_when_lease_release_needs_retry() {
        let release_attempts = Arc::new(AtomicU64::new(0));
        let attempts = Arc::clone(&release_attempts);
        let release = Box::new(move || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(QueryFailure::new(QueryFailureCode::StoreUnavailable))
            } else {
                Ok(())
            }
        });
        let stats = empty_stats();
        let mut stream = QueryStream::new(
            vec![QueryEvent::Terminal(QueryTerminal::Complete(stats))],
            Some(release),
            false,
            stats,
            stats,
            crate::QueryCancellation::new(),
            None,
        );

        assert_eq!(
            format!("{stream:?}"),
            "QueryStream { <bounded-events> }",
            "stream diagnostics must not expose retained result data"
        );

        assert_eq!(
            stream.cancel().expect_err("first release fails").code(),
            QueryFailureCode::StoreUnavailable
        );
        assert!(matches!(
            stream.next(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::StoreUnavailable
        ));
        stream.cancel().expect("idempotent release retry succeeds");
        assert!(stream.next().is_none());
        assert_eq!(release_attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retained_cancellation_surfaces_cleanup_failure_and_retries_on_drop() {
        let release_attempts = Arc::new(AtomicU64::new(0));
        let attempts = Arc::clone(&release_attempts);
        let release = Box::new(move || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(QueryFailure::new(QueryFailureCode::StoreUnavailable))
            } else {
                Ok(())
            }
        });
        let stats = empty_stats();
        let cancellation = crate::QueryCancellation::new();
        let retained = cancellation.clone();
        let mut stream = QueryStream::new(
            vec![
                QueryEvent::Header(test_header()),
                QueryEvent::Terminal(QueryTerminal::Complete(stats)),
            ],
            Some(release),
            false,
            stats,
            stats,
            cancellation,
            None,
        );

        retained.cancel();
        assert!(matches!(stream.next(), Some(QueryEvent::Header(_))));
        assert!(matches!(
            stream.next(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::StoreUnavailable
                    && incomplete.stats() == stats
        ));
        assert!(stream.next().is_none());
        assert_eq!(release_attempts.load(Ordering::SeqCst), 1);
        drop(stream);
        assert_eq!(release_attempts.load(Ordering::SeqCst), 2);
    }

    fn empty_stats() -> QueryStats {
        QueryStats::new(
            QueryCounters {
                records: 0,
                scanned_bytes: 0,
                decoded_records: 0,
                output_bytes: 0,
                memory_peak_bytes: 0,
                cpu_work_units: 0,
                wall_seconds: 0,
            },
            None,
            [0; 32],
        )
    }

    fn test_header() -> QueryHeader {
        let range = TemporalRange::new(0, 1).expect("test range is valid");
        let plan = LogicalPlan::logs(TemporalAxis::QueryTime, range, 1);
        let budget = QueryBudget::new(1, 1, 1, 1, 1, 1).expect("test budget is valid");
        QueryHeader::new(
            &plan,
            budget,
            ResultSnapshot::new([1; 32], 1, 1),
            ResultLease::new([2; 16], 1),
            None,
        )
        .expect("test header allocation succeeds")
    }
}
