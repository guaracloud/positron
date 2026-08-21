use crate::{
    QueryEvent, QueryFailure, QueryFailureCode, QueryIncomplete, QueryStats, QueryTerminal,
};

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
        }
    }

    pub fn cancel(&mut self) -> Result<(), QueryFailure> {
        self.cancellation.cancel();
        self.replace_pending_with_cancelled();
        self.release_lease()?;
        Ok(())
    }

    fn replace_pending_with_cancelled(&mut self) {
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
                QueryIncomplete::new(
                    QueryFailure::new(QueryFailureCode::Cancelled),
                    self.observed_stats,
                ),
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
        if self.cancellation.is_cancelled() && !self.terminal_observed {
            self.replace_pending_with_cancelled();
            let _ = self.release_lease();
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
            let _ = release();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::QueryStream;
    use crate::stream::QueryCounters;
    use crate::{QueryEvent, QueryFailure, QueryFailureCode, QueryStats, QueryTerminal};

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
        );

        assert_eq!(
            stream.cancel().expect_err("first release fails").code(),
            QueryFailureCode::StoreUnavailable
        );
        assert!(matches!(
            stream.next(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::Cancelled
        ));
        stream.cancel().expect("idempotent release retry succeeds");
        assert!(stream.next().is_none());
        assert_eq!(release_attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retained_cancellation_retries_a_failed_release_after_one_cancelled_terminal() {
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
            vec![QueryEvent::Terminal(QueryTerminal::Complete(stats))],
            Some(release),
            false,
            stats,
            stats,
            cancellation,
        );

        retained.cancel();
        assert!(matches!(
            stream.next(),
            Some(QueryEvent::Terminal(QueryTerminal::Incomplete(incomplete)))
                if incomplete.code() == QueryFailureCode::Cancelled
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
                cpu_work_units: 0,
                wall_seconds: 0,
            },
            None,
            [0; 32],
        )
    }
}
