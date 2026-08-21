use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_domain::time::UnixNanoseconds;

use crate::{LogicalPlan, QueryBudget, QueryCursor, QueryFailure, QueryFailureCode, TemporalAxis};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultSchema {
    columns: Vec<&'static str>,
}

impl ResultSchema {
    pub(crate) fn for_plan(plan: &LogicalPlan) -> Self {
        if let Some(aggregate) = plan.aggregate() {
            let mut columns = aggregate
                .group_by()
                .iter()
                .map(column_name)
                .collect::<Vec<_>>();
            columns.push("count");
            return Self { columns };
        }
        let columns = plan.projection().iter().map(column_name).collect();
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

fn column_name(column: &crate::plan::ProjectionColumn) -> &'static str {
    match column {
        crate::plan::ProjectionColumn::Body => "body",
        crate::plan::ProjectionColumn::QueryTime => "query_time",
        crate::plan::ProjectionColumn::CommitPosition => "commit_position",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultOrdering {
    columns: Vec<&'static str>,
    directions: Vec<crate::OrderDirection>,
}

impl ResultOrdering {
    pub(crate) fn for_plan(plan: &LogicalPlan) -> Self {
        if let Some(aggregate) = plan.aggregate() {
            return Self {
                columns: aggregate.group_by().iter().map(column_name).collect(),
                directions: vec![crate::OrderDirection::Ascending; aggregate.group_by().len()],
            };
        }
        Self {
            columns: vec![
                match plan.temporal_axis() {
                    TemporalAxis::QueryTime => "query_time",
                    TemporalAxis::EventTime => "event_time",
                },
                "commit_position",
                "record_ordinal",
            ],
            directions: vec![
                plan.ordering().primary_direction(),
                plan.ordering().commit_direction(),
                plan.ordering().commit_direction(),
            ],
        }
    }

    #[must_use]
    pub fn columns(&self) -> &[&'static str] {
        &self.columns
    }

    #[must_use]
    pub fn directions(&self) -> &[crate::OrderDirection] {
        &self.directions
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
    schema: ResultSchema,
    ordering: ResultOrdering,
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
            ordering: ResultOrdering::for_plan(&plan),
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
    pub fn ordering(&self) -> ResultOrdering {
        self.ordering.clone()
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
    record_ordinal: RecordOrdinal,
    query_time_selected: bool,
    commit_position_selected: bool,
    count: Option<u64>,
}

impl QueryRecord {
    pub(crate) const fn new(
        body: Option<String>,
        query_time: UnixNanoseconds,
        commit_position: CommitPosition,
        record_ordinal: RecordOrdinal,
        query_time_selected: bool,
        commit_position_selected: bool,
    ) -> Self {
        Self {
            body,
            query_time,
            commit_position,
            record_ordinal,
            query_time_selected,
            commit_position_selected,
            count: None,
        }
    }

    pub(crate) const fn count_record(count: u64) -> Self {
        Self {
            body: None,
            query_time: UnixNanoseconds::new(0),
            commit_position: CommitPosition::origin(),
            record_ordinal: RecordOrdinal::first(),
            query_time_selected: false,
            commit_position_selected: false,
            count: Some(count),
        }
    }

    pub(crate) fn grouped_count_record(
        body: Option<String>,
        query_time: Option<UnixNanoseconds>,
        commit_position: Option<CommitPosition>,
        count: u64,
    ) -> Self {
        Self {
            body,
            query_time: query_time.unwrap_or_else(|| UnixNanoseconds::new(0)),
            commit_position: commit_position.unwrap_or_else(CommitPosition::origin),
            record_ordinal: RecordOrdinal::first(),
            query_time_selected: query_time.is_some(),
            commit_position_selected: commit_position.is_some(),
            count: Some(count),
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
    /// Returns the final intrinsic component of this record's total order.
    #[must_use]
    pub const fn record_ordinal(&self) -> RecordOrdinal {
        self.record_ordinal
    }
    #[must_use]
    pub const fn count(&self) -> Option<u64> {
        self.count
    }

    pub(crate) fn emitted_size_bytes(&self) -> Result<u64, QueryFailure> {
        let body_bytes = u64::try_from(self.body_text().map_or(0, str::len))
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))?;
        let query_time_bytes = u64::from(self.query_time_selected) * 8;
        let commit_position_bytes = u64::from(self.commit_position_selected) * 8;
        let count_bytes = u64::from(self.count.is_some()) * 8;
        body_bytes
            .checked_add(query_time_bytes)
            .and_then(|bytes| bytes.checked_add(commit_position_bytes))
            .and_then(|bytes| bytes.checked_add(count_bytes))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))
    }

    pub(crate) const fn order_key(&self) -> (UnixNanoseconds, CommitPosition, RecordOrdinal) {
        (self.query_time, self.commit_position, self.record_ordinal)
    }

    pub(crate) fn retained_dynamic_bytes(&self) -> Result<u64, QueryFailure> {
        u64::try_from(self.body_text().map_or(0, str::len))
            .map_err(|_| QueryFailure::new(QueryFailureCode::Internal))
    }

    pub(crate) fn into_group_fields(self) -> (Option<String>, UnixNanoseconds, CommitPosition) {
        (self.body, self.query_time, self.commit_position)
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
