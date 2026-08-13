use positron_domain::routing::CommitPosition;
use positron_domain::time::UnixNanoseconds;

use crate::{LogicalPlan, QueryBudget, QueryCursor, QueryFailure, QueryFailureCode, TemporalAxis};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultSchema;

impl ResultSchema {
    #[must_use]
    pub const fn columns(self) -> [&'static str; 1] {
        ["body"]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultSnapshot {
    identity: [u8; 32],
    generation: u64,
    frontier: u64,
}

impl ResultSnapshot {
    pub(crate) const fn new(identity: [u8; 32], generation: u64, frontier: u64) -> Self {
        Self {
            identity,
            generation,
            frontier,
        }
    }
    #[must_use]
    pub const fn identity(self) -> [u8; 32] {
        self.identity
    }
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn frontier(self) -> u64 {
        self.frontier
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultOrdering(TemporalAxis);

impl ResultOrdering {
    #[must_use]
    pub const fn columns(self) -> [&'static str; 2] {
        [
            match self.0 {
                TemporalAxis::QueryTime => "query_time",
                TemporalAxis::EventTime => "event_time",
            },
            "commit_position",
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultLease {
    identity: [u8; 16],
    expiry: u64,
}

impl ResultLease {
    pub(crate) const fn new(identity: [u8; 16], expiry: u64) -> Self {
        Self { identity, expiry }
    }
    #[must_use]
    pub const fn identity(self) -> [u8; 16] {
        self.identity
    }
    #[must_use]
    pub const fn expiry(self) -> u64 {
        self.expiry
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryHeader {
    plan: LogicalPlan,
    budget: QueryBudget,
    snapshot: ResultSnapshot,
    lease: ResultLease,
    initial_cursor: Option<QueryCursor>,
}

impl QueryHeader {
    pub(crate) const fn new(
        plan: LogicalPlan,
        budget: QueryBudget,
        snapshot: ResultSnapshot,
        lease: ResultLease,
        initial_cursor: Option<QueryCursor>,
    ) -> Self {
        Self {
            plan,
            budget,
            snapshot,
            lease,
            initial_cursor,
        }
    }
    #[must_use]
    pub const fn schema(&self) -> ResultSchema {
        ResultSchema
    }
    #[must_use]
    pub const fn snapshot(&self) -> ResultSnapshot {
        self.snapshot
    }
    #[must_use]
    pub const fn ordering(&self) -> ResultOrdering {
        ResultOrdering(self.plan.temporal_axis())
    }
    #[must_use]
    pub const fn budget(&self) -> QueryBudget {
        self.budget
    }
    #[must_use]
    pub const fn lease(&self) -> ResultLease {
        self.lease
    }
    #[must_use]
    pub const fn initial_cursor(&self) -> Option<&QueryCursor> {
        self.initial_cursor.as_ref()
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
    prior_digest: [u8; 32],
    digest: [u8; 32],
}

impl QueryBatch {
    pub(crate) const fn new(
        sequence: u64,
        records: Vec<QueryRecord>,
        prior_digest: [u8; 32],
        digest: [u8; 32],
    ) -> Self {
        Self {
            sequence,
            records,
            prior_digest,
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
    pub const fn prior_digest(&self) -> [u8; 32] {
        self.prior_digest
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
    last_sequence: Option<u64>,
    result_digest: [u8; 32],
}

impl QueryStats {
    pub(crate) const fn new(
        records: u64,
        scanned_bytes: u64,
        last_sequence: Option<u64>,
        result_digest: [u8; 32],
    ) -> Self {
        Self {
            records,
            scanned_bytes,
            last_sequence,
            result_digest,
        }
    }
    #[must_use]
    pub const fn records(self) -> u64 {
        self.records
    }
    #[must_use]
    pub const fn scanned_bytes(self) -> u64 {
        self.scanned_bytes
    }
    #[must_use]
    pub const fn last_sequence(self) -> Option<u64> {
        self.last_sequence
    }
    #[must_use]
    pub const fn result_digest(self) -> [u8; 32] {
        self.result_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryIncomplete {
    failure: QueryFailure,
    stats: QueryStats,
}

impl QueryIncomplete {
    pub(crate) const fn new(failure: QueryFailure, stats: QueryStats) -> Self {
        Self { failure, stats }
    }
    #[must_use]
    pub const fn code(&self) -> QueryFailureCode {
        self.failure.code()
    }
    #[must_use]
    pub const fn stats(&self) -> QueryStats {
        self.stats
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryTerminal {
    Complete(QueryStats),
    Continued(QueryCursor),
    Incomplete(QueryIncomplete),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryEvent {
    Header(QueryHeader),
    Batch(QueryBatch),
    Terminal(QueryTerminal),
}

type LeaseRelease<'lease> = Box<dyn FnOnce() -> Result<(), QueryFailure> + 'lease>;

pub struct QueryStream<'lease> {
    events: std::vec::IntoIter<QueryEvent>,
    terminal_observed: bool,
    release: Option<LeaseRelease<'lease>>,
}

impl std::fmt::Debug for QueryStream<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueryStream { <bounded-events> }")
    }
}

impl<'lease> QueryStream<'lease> {
    pub(crate) fn new(events: Vec<QueryEvent>, release: LeaseRelease<'lease>) -> Self {
        Self {
            events: events.into_iter(),
            terminal_observed: false,
            release: Some(release),
        }
    }
    pub fn cancel(&mut self) -> Result<(), QueryFailure> {
        if self.terminal_observed {
            self.events = Vec::new().into_iter();
            return Ok(());
        }
        if let Some(release) = self.release.take() {
            release()?;
        }
        self.events = vec![QueryEvent::Terminal(QueryTerminal::Incomplete(
            QueryIncomplete::new(
                QueryFailure::new(QueryFailureCode::Cancelled),
                QueryStats::new(0, 0, None, [0; 32]),
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
        if matches!(event, Some(QueryEvent::Terminal(_))) {
            self.terminal_observed = true;
        }
        event
    }
}
