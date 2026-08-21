use crate::{
    QueryEvent, QueryFailure, QueryFailureCode, QueryIncomplete, QueryStats, QueryTerminal,
};

type LeaseRelease<'lease> = Box<dyn FnOnce() -> Result<(), QueryFailure> + 'lease>;

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
        if let Some(release) = self.release.take() {
            release()?;
        }
        if self.terminal_observed {
            self.events = Vec::new().into_iter();
            return Ok(());
        }
        self.events = vec![QueryEvent::Terminal(QueryTerminal::Incomplete(
            QueryIncomplete::new(
                QueryFailure::new(QueryFailureCode::Cancelled),
                self.observed_stats,
            ),
        ))]
        .into_iter();
        Ok(())
    }
}

impl Iterator for QueryStream<'_> {
    type Item = QueryEvent;

    fn next(&mut self) -> Option<Self::Item> {
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
            && let Some(release) = self.release.take()
        {
            let _ = release();
        }
    }
}
