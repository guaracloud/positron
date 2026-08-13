use positron_domain::routing::CommitPosition;
use positron_domain::time::UnixNanoseconds;

use crate::{LogicalPlan, QueryBudget, QueryFailure, QueryFailureCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryHeader {
    plan: LogicalPlan,
    budget: QueryBudget,
}

impl QueryHeader {
    pub(crate) const fn new(plan: LogicalPlan, budget: QueryBudget) -> Self {
        Self { plan, budget }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryRecord {
    body: Option<String>,
    query_time: UnixNanoseconds,
    commit_position: CommitPosition,
}

impl QueryRecord {
    pub(crate) const fn new(
        body: Option<String>,
        query_time: UnixNanoseconds,
        commit_position: CommitPosition,
    ) -> Self {
        Self {
            body,
            query_time,
            commit_position,
        }
    }

    #[must_use]
    pub fn body_text(&self) -> Option<&str> {
        self.body.as_deref()
    }

    pub(crate) const fn order_key(&self) -> (UnixNanoseconds, CommitPosition) {
        (self.query_time, self.commit_position)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryBatch {
    sequence: u64,
    records: Vec<QueryRecord>,
    digest: [u8; 32],
}

impl QueryBatch {
    pub(crate) const fn new(sequence: u64, records: Vec<QueryRecord>, digest: [u8; 32]) -> Self {
        Self {
            sequence,
            records,
            digest,
        }
    }

    #[must_use]
    pub fn records(&self) -> &[QueryRecord] {
        &self.records
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryStats {
    records: u64,
    scanned_bytes: u64,
}

impl QueryStats {
    pub(crate) const fn new(records: u64, scanned_bytes: u64) -> Self {
        Self {
            records,
            scanned_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryTerminal {
    Complete(QueryStats),
    Continued(crate::QueryCursor),
    Incomplete(QueryFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryEvent {
    Header(QueryHeader),
    Batch(QueryBatch),
    Terminal(QueryTerminal),
}

#[derive(Debug)]
pub struct QueryStream {
    events: std::vec::IntoIter<QueryEvent>,
    terminal_observed: bool,
}

impl QueryStream {
    pub(crate) fn new(events: Vec<QueryEvent>) -> Self {
        Self {
            events: events.into_iter(),
            terminal_observed: false,
        }
    }

    /// Cooperatively cancels an admitted response before its terminal event is
    /// observed. Any unsent batch or completion is replaced by one typed
    /// non-complete terminal.
    pub fn cancel(&mut self) {
        if self.terminal_observed {
            self.events = Vec::new().into_iter();
            return;
        }
        self.events = vec![QueryEvent::Terminal(QueryTerminal::Incomplete(
            QueryFailure::new(QueryFailureCode::Cancelled),
        ))]
        .into_iter();
    }
}

impl Iterator for QueryStream {
    type Item = QueryEvent;

    fn next(&mut self) -> Option<Self::Item> {
        let event = self.events.next();
        if matches!(event, Some(QueryEvent::Terminal(_))) {
            self.terminal_observed = true;
        }
        event
    }
}
