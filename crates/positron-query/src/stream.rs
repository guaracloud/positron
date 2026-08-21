use positron_domain::routing::{CommitPosition, RecordOrdinal};
use positron_domain::time::{EventTime, QueryTime, UnixNanoseconds};
use positron_kernel::IngestTime;

use crate::{LogicalPlan, QueryBudget, QueryCursor, QueryFailure, QueryFailureCode, TemporalAxis};

/// A stable logical type carried by a result column or hidden ordering key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultValueType {
    /// A lossless bounded dynamic value, including native null and containers.
    NativeValue,
    /// A signed Unix timestamp measured in nanoseconds.
    UnixNanoseconds,
    /// An optional signed Unix timestamp; absence is a first-class value.
    OptionalUnixNanoseconds,
    /// A selected log Query Time with its source provenance.
    QueryTime,
    /// An exact source Event Time with its quality, including Missing.
    EventTime,
    /// A Storage Kernel-assigned Ingest Time.
    IngestTime,
    /// A monotonically increasing committed block position.
    CommitPosition,
    /// A record's stable ordinal within its committed block.
    RecordOrdinal,
    /// An unsigned integer aggregate.
    UnsignedInteger,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultSchema {
    columns: Vec<&'static str>,
    types: Vec<ResultValueType>,
}

impl ResultSchema {
    pub(crate) fn for_plan(plan: &LogicalPlan) -> Self {
        if let Some(aggregate) = plan.aggregate() {
            let mut columns = aggregate
                .group_by()
                .iter()
                .map(column_name)
                .collect::<Vec<_>>();
            let mut types = aggregate
                .group_by()
                .iter()
                .copied()
                .map(column_type)
                .collect::<Vec<_>>();
            columns.push("count");
            types.push(ResultValueType::UnsignedInteger);
            return Self { columns, types };
        }
        let columns = plan.projection().iter().map(column_name).collect();
        let types = plan.projection().iter().copied().map(column_type).collect();
        Self { columns, types }
    }

    #[must_use]
    pub fn columns(&self) -> Vec<&'static str> {
        self.columns.clone()
    }

    /// Returns a type descriptor for each result column in the same order as [`Self::columns`].
    #[must_use]
    pub fn types(&self) -> &[ResultValueType] {
        &self.types
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
        crate::plan::ProjectionColumn::EventTime => "event_time",
        crate::plan::ProjectionColumn::IngestTime => "ingest_time",
        crate::plan::ProjectionColumn::CommitPosition => "commit_position",
    }
}

pub(crate) const fn column_type(column: crate::plan::ProjectionColumn) -> ResultValueType {
    match column {
        crate::plan::ProjectionColumn::Body => ResultValueType::NativeValue,
        crate::plan::ProjectionColumn::QueryTime => ResultValueType::QueryTime,
        crate::plan::ProjectionColumn::EventTime => ResultValueType::EventTime,
        crate::plan::ProjectionColumn::IngestTime => ResultValueType::IngestTime,
        crate::plan::ProjectionColumn::CommitPosition => ResultValueType::CommitPosition,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultOrdering {
    columns: Vec<&'static str>,
    types: Vec<ResultValueType>,
    directions: Vec<crate::OrderDirection>,
}

impl ResultOrdering {
    pub(crate) fn for_plan(plan: &LogicalPlan) -> Self {
        if let Some(aggregate) = plan.aggregate() {
            return Self {
                columns: aggregate.group_by().iter().map(column_name).collect(),
                types: aggregate
                    .group_by()
                    .iter()
                    .copied()
                    .map(column_type)
                    .collect(),
                directions: vec![crate::OrderDirection::Ascending; aggregate.group_by().len()],
            };
        }
        Self {
            columns: vec![
                match plan.temporal_axis() {
                    TemporalAxis::QueryTime => "query_time",
                    TemporalAxis::EventTime => "event_time",
                    TemporalAxis::IngestTime => "ingest_time",
                },
                "commit_position",
                "record_ordinal",
            ],
            types: vec![
                match plan.temporal_axis() {
                    TemporalAxis::QueryTime => ResultValueType::QueryTime,
                    TemporalAxis::EventTime => ResultValueType::EventTime,
                    TemporalAxis::IngestTime => ResultValueType::IngestTime,
                },
                ResultValueType::CommitPosition,
                ResultValueType::RecordOrdinal,
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

    /// Returns a type descriptor for each total-order key in [`Self::columns`].
    #[must_use]
    pub fn types(&self) -> &[ResultValueType] {
        &self.types
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
    body: Option<positron_domain::value::ValidatedAttributeValue>,
    body_retained_bytes: u64,
    body_selected: bool,
    query_time: Option<QueryTime>,
    event_time: Option<EventTime>,
    ingest_time: Option<IngestTime>,
    ordering_time: UnixNanoseconds,
    commit_position: CommitPosition,
    record_ordinal: RecordOrdinal,
    query_time_selected: bool,
    event_time_selected: bool,
    ingest_time_selected: bool,
    commit_position_selected: bool,
    count: Option<u64>,
}

pub(crate) struct QueryRecordTimes {
    pub(crate) query: QueryTime,
    pub(crate) event: EventTime,
    pub(crate) ingest: IngestTime,
    pub(crate) ordering: UnixNanoseconds,
}

pub(crate) struct QueryRecordSelection {
    pub(crate) body: bool,
    pub(crate) query_time: bool,
    pub(crate) event_time: bool,
    pub(crate) ingest_time: bool,
    pub(crate) commit_position: bool,
}

pub(crate) struct QueryGroupFields {
    pub(crate) body: Option<positron_domain::value::ValidatedAttributeValue>,
    pub(crate) body_retained_bytes: u64,
    pub(crate) query_time: QueryTime,
    pub(crate) event_time: EventTime,
    pub(crate) ingest_time: IngestTime,
    pub(crate) commit_position: CommitPosition,
}

pub(crate) struct GroupedCountFields {
    pub(crate) body: Option<positron_domain::value::ValidatedAttributeValue>,
    pub(crate) body_retained_bytes: u64,
    pub(crate) body_selected: bool,
    pub(crate) query_time: Option<QueryTime>,
    pub(crate) event_time: Option<EventTime>,
    pub(crate) ingest_time: Option<IngestTime>,
    pub(crate) commit_position: Option<CommitPosition>,
}

impl QueryRecord {
    pub(crate) const fn new(
        body: Option<positron_domain::value::ValidatedAttributeValue>,
        body_retained_bytes: u64,
        times: QueryRecordTimes,
        commit_position: CommitPosition,
        record_ordinal: RecordOrdinal,
        selection: QueryRecordSelection,
    ) -> Self {
        Self {
            body,
            body_retained_bytes,
            body_selected: selection.body,
            query_time: Some(times.query),
            event_time: Some(times.event),
            ingest_time: Some(times.ingest),
            ordering_time: times.ordering,
            commit_position,
            record_ordinal,
            query_time_selected: selection.query_time,
            event_time_selected: selection.event_time,
            ingest_time_selected: selection.ingest_time,
            commit_position_selected: selection.commit_position,
            count: None,
        }
    }

    pub(crate) const fn count_record(count: u64) -> Self {
        Self {
            body: None,
            body_retained_bytes: 0,
            body_selected: false,
            query_time: None,
            event_time: None,
            ingest_time: None,
            ordering_time: UnixNanoseconds::new(0),
            commit_position: CommitPosition::origin(),
            record_ordinal: RecordOrdinal::first(),
            query_time_selected: false,
            event_time_selected: false,
            ingest_time_selected: false,
            commit_position_selected: false,
            count: Some(count),
        }
    }

    pub(crate) fn grouped_count_record(fields: GroupedCountFields, count: u64) -> Self {
        Self {
            body: fields.body,
            body_retained_bytes: fields.body_retained_bytes,
            body_selected: fields.body_selected,
            query_time: fields.query_time,
            event_time: fields.event_time,
            ingest_time: fields.ingest_time,
            ordering_time: UnixNanoseconds::new(0),
            commit_position: fields
                .commit_position
                .unwrap_or_else(CommitPosition::origin),
            record_ordinal: RecordOrdinal::first(),
            query_time_selected: fields.query_time.is_some(),
            event_time_selected: fields.event_time.is_some(),
            ingest_time_selected: fields.ingest_time.is_some(),
            commit_position_selected: fields.commit_position.is_some(),
            count: Some(count),
        }
    }
    #[must_use]
    pub fn body_text(&self) -> Option<&str> {
        self.body.as_ref().and_then(|body| body.as_str())
    }
    /// Returns the complete native body without coercion when body is selected and present.
    #[must_use]
    pub const fn body_value(&self) -> Option<&positron_domain::value::ValidatedAttributeValue> {
        self.body.as_ref()
    }
    #[must_use]
    pub const fn query_time(&self) -> UnixNanoseconds {
        match self.query_time {
            Some(query_time) => query_time.instant(),
            None => UnixNanoseconds::new(0),
        }
    }
    /// Returns Query Time with the provenance selected by the domain fallback rules.
    #[must_use]
    pub const fn query_time_value(&self) -> Option<QueryTime> {
        self.query_time
    }
    /// Returns Event Time exactly as received; missing Event Time remains absent.
    #[must_use]
    pub const fn event_time(&self) -> Option<UnixNanoseconds> {
        match self.event_time {
            Some(event_time) => event_time.instant(),
            None => None,
        }
    }
    /// Returns the exact Event Time and its source quality, including Missing.
    #[must_use]
    pub const fn event_time_value(&self) -> Option<EventTime> {
        self.event_time
    }
    /// Returns the Storage Kernel-assigned Ingest Time when this row represents a record.
    #[must_use]
    pub const fn ingest_time_value(&self) -> Option<IngestTime> {
        self.ingest_time
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
        let body_bytes = if self.body_selected {
            let encoded = self
                .body
                .as_ref()
                .map_or(Ok(0), |body| body.canonical_encoded_size_bytes())
                .map_err(map_value_failure)?;
            u64::try_from(encoded)
                .ok()
                .and_then(|encoded| encoded.checked_add(1))
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?
        } else {
            0
        };
        let query_time_bytes = if self.query_time_selected {
            self.query_time
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            9
        } else {
            0
        };
        let event_time_bytes = if self.event_time_selected {
            let event_time = self
                .event_time
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            2 + u64::from(event_time.instant().is_some()) * 8
        } else {
            0
        };
        let ingest_time_bytes = if self.ingest_time_selected {
            self.ingest_time
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?;
            8
        } else {
            0
        };
        let commit_position_bytes = u64::from(self.commit_position_selected) * 8;
        let count_bytes = u64::from(self.count.is_some()) * 8;
        body_bytes
            .checked_add(query_time_bytes)
            .and_then(|bytes| bytes.checked_add(event_time_bytes))
            .and_then(|bytes| bytes.checked_add(ingest_time_bytes))
            .and_then(|bytes| bytes.checked_add(commit_position_bytes))
            .and_then(|bytes| bytes.checked_add(count_bytes))
            .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))
    }

    pub(crate) const fn order_key(&self) -> (UnixNanoseconds, CommitPosition, RecordOrdinal) {
        (
            self.ordering_time,
            self.commit_position,
            self.record_ordinal,
        )
    }

    pub(crate) const fn ordering_time(&self) -> UnixNanoseconds {
        self.ordering_time
    }

    pub(crate) fn retained_dynamic_bytes(&self) -> Result<u64, QueryFailure> {
        Ok(self.body_retained_bytes)
    }

    pub(crate) fn into_group_fields(self) -> Result<QueryGroupFields, QueryFailure> {
        Ok(QueryGroupFields {
            body: self.body,
            body_retained_bytes: self.body_retained_bytes,
            query_time: self
                .query_time
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            event_time: self
                .event_time
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            ingest_time: self
                .ingest_time
                .ok_or_else(|| QueryFailure::new(QueryFailureCode::Internal))?,
            commit_position: self.commit_position,
        })
    }

    pub(crate) const fn query_time_selected(&self) -> bool {
        self.query_time_selected
    }

    pub(crate) const fn event_time_selected(&self) -> bool {
        self.event_time_selected
    }

    pub(crate) const fn ingest_time_selected(&self) -> bool {
        self.ingest_time_selected
    }
}

fn map_value_failure(failure: positron_domain::outcome::DomainFailure) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        QueryFailure::new(QueryFailureCode::Internal)
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
