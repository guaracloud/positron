use crate::{LogicalPlan, QueryBudget, QueryCursor, QueryFailure, TemporalAxis};

/// A stable logical type carried by a result column or hidden ordering key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultValueType {
    NativeValue,
    UnixNanoseconds,
    OptionalUnixNanoseconds,
    QueryTime,
    EventTime,
    IngestTime,
    CommitPosition,
    RecordOrdinal,
    UnsignedInteger,
    AttributeOccurrenceSet,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultSchema {
    columns: Vec<String>,
    types: Vec<ResultValueType>,
    nullable: Vec<bool>,
}

impl ResultSchema {
    fn for_plan(plan: &LogicalPlan) -> Result<Self, QueryFailure> {
        if let Some(aggregate) = plan.aggregate() {
            let mut columns = aggregate
                .group_by()
                .iter()
                .map(column_name)
                .collect::<Result<Vec<_>, _>>()?;
            let mut types = aggregate
                .group_by()
                .iter()
                .map(column_type)
                .collect::<Vec<_>>();
            let mut nullable = aggregate
                .group_by()
                .iter()
                .map(column_nullable)
                .collect::<Vec<_>>();
            columns.push("count".to_owned());
            types.push(ResultValueType::UnsignedInteger);
            nullable.push(false);
            return Ok(Self {
                columns,
                types,
                nullable,
            });
        }
        Ok(Self {
            columns: plan
                .projection()
                .iter()
                .map(column_name)
                .collect::<Result<Vec<_>, _>>()?,
            types: plan.projection().iter().map(column_type).collect(),
            nullable: plan.projection().iter().map(column_nullable).collect(),
        })
    }

    #[must_use]
    pub fn columns(&self) -> Vec<&str> {
        self.columns.iter().map(String::as_str).collect()
    }
    #[must_use]
    pub fn types(&self) -> &[ResultValueType] {
        &self.types
    }
    #[must_use]
    pub fn nullable(&self) -> &[bool] {
        &self.nullable
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

fn column_name(column: &crate::plan::ProjectionColumn) -> Result<String, QueryFailure> {
    Ok(match column {
        crate::plan::ProjectionColumn::Body => "body".to_owned(),
        crate::plan::ProjectionColumn::QueryTime => "query_time".to_owned(),
        crate::plan::ProjectionColumn::EventTime => "event_time".to_owned(),
        crate::plan::ProjectionColumn::IngestTime => "ingest_time".to_owned(),
        crate::plan::ProjectionColumn::CommitPosition => "commit_position".to_owned(),
        crate::plan::ProjectionColumn::Attribute(path) => {
            crate::attribute_syntax::render_path(path)?
        },
    })
}

pub(crate) const fn column_type(column: &crate::plan::ProjectionColumn) -> ResultValueType {
    match column {
        crate::plan::ProjectionColumn::Body => ResultValueType::NativeValue,
        crate::plan::ProjectionColumn::QueryTime => ResultValueType::QueryTime,
        crate::plan::ProjectionColumn::EventTime => ResultValueType::EventTime,
        crate::plan::ProjectionColumn::IngestTime => ResultValueType::IngestTime,
        crate::plan::ProjectionColumn::CommitPosition => ResultValueType::CommitPosition,
        crate::plan::ProjectionColumn::Attribute(_) => ResultValueType::AttributeOccurrenceSet,
    }
}

const fn column_nullable(column: &crate::plan::ProjectionColumn) -> bool {
    matches!(
        column,
        crate::plan::ProjectionColumn::Body | crate::plan::ProjectionColumn::Attribute(_)
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultOrdering {
    columns: Vec<String>,
    types: Vec<ResultValueType>,
    directions: Vec<crate::OrderDirection>,
}

impl ResultOrdering {
    fn for_plan(plan: &LogicalPlan) -> Result<Self, QueryFailure> {
        if let Some(aggregate) = plan.aggregate() {
            return Ok(Self {
                columns: aggregate
                    .group_by()
                    .iter()
                    .map(column_name)
                    .collect::<Result<Vec<_>, _>>()?,
                types: aggregate.group_by().iter().map(column_type).collect(),
                directions: vec![crate::OrderDirection::Ascending; aggregate.group_by().len()],
            });
        }
        Ok(Self {
            columns: vec![
                match plan.temporal_axis() {
                    TemporalAxis::QueryTime => "query_time".to_owned(),
                    TemporalAxis::EventTime => "event_time".to_owned(),
                    TemporalAxis::IngestTime => "ingest_time".to_owned(),
                },
                "commit_position".to_owned(),
                "record_ordinal".to_owned(),
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
        })
    }
    #[must_use]
    pub fn columns(&self) -> Vec<&str> {
        self.columns.iter().map(String::as_str).collect()
    }
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
    ) -> Result<Self, QueryFailure> {
        Ok(Self {
            schema: ResultSchema::for_plan(&plan)?,
            ordering: ResultOrdering::for_plan(&plan)?,
            budget,
            snapshot,
            lease,
            initial_cursor,
        })
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
