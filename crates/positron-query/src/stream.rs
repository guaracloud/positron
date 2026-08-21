use positron_domain::routing::CommitPosition;
use positron_domain::time::UnixNanoseconds;

use crate::{LogicalPlan, QueryBudget, QueryCursor, QueryFailure, QueryFailureCode, TemporalAxis};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultSchema {
    columns: Vec<&'static str>,
}

impl ResultSchema {
    pub(crate) fn for_plan(plan: &LogicalPlan) -> Self {
        let columns = plan
            .projection()
            .iter()
            .map(|column| match column {
                crate::plan::ProjectionColumn::Body => "body",
                crate::plan::ProjectionColumn::QueryTime => "query_time",
                crate::plan::ProjectionColumn::CommitPosition => "commit_position",
            })
            .collect();
        Self { columns }
    }

    #[must_use]
    pub fn columns(&self) -> Vec<&'static str> {
        self.columns.clone()
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
    schema: ResultSchema,
    budget: QueryBudget,
    snapshot: ResultSnapshot,
    lease: ResultLease,
    initial_cursor: Option<QueryCursor>,
}

impl QueryHeader {
    pub(crate) fn new(
        plan: LogicalPlan,
        budget: QueryBudget,
        snapshot: ResultSnapshot,
        lease: ResultLease,
        initial_cursor: Option<QueryCursor>,
    ) -> Self {
        Self {
            schema: ResultSchema::for_plan(&plan),
            plan,
            budget,
            snapshot,
            lease,
            initial_cursor,
        }
    }
    #[must_use]
    pub fn schema(&self) -> &ResultSchema {
        &self.schema
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
    #[must_use]
    pub const fn query_time(&self) -> UnixNanoseconds {
        self.query_time
    }
    #[must_use]
    pub const fn commit_position(&self) -> CommitPosition {
        self.commit_position
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
    decoded_records: u64,
    output_bytes: u64,
    cpu_work_units: u64,
    wall_seconds: u64,
    last_sequence: Option<u64>,
    result_digest: [u8; 32],
}

pub(crate) struct QueryCounters {
    pub(crate) records: u64,
    pub(crate) scanned_bytes: u64,
    pub(crate) decoded_records: u64,
    pub(crate) output_bytes: u64,
    pub(crate) cpu_work_units: u64,
    pub(crate) wall_seconds: u64,
}

impl QueryStats {
    pub(crate) const fn new(
        counters: QueryCounters,
        last_sequence: Option<u64>,
        result_digest: [u8; 32],
    ) -> Self {
        Self {
            records: counters.records,
            scanned_bytes: counters.scanned_bytes,
            decoded_records: counters.decoded_records,
            output_bytes: counters.output_bytes,
            cpu_work_units: counters.cpu_work_units,
            wall_seconds: counters.wall_seconds,
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
    pub const fn decoded_records(self) -> u64 {
        self.decoded_records
    }
    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }
    #[must_use]
    pub const fn cpu_work_units(self) -> u64 {
        self.cpu_work_units
    }
    #[must_use]
    pub const fn wall_seconds(self) -> u64 {
        self.wall_seconds
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
