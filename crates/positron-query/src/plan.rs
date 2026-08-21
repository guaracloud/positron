use positron_governance::AuthorizedContext;
use positron_kernel::ResourceReservation;

use crate::QueryBudget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalAxis {
    QueryTime,
    EventTime,
    IngestTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemporalRange {
    start_nanoseconds: i64,
    end_nanoseconds: i64,
}

impl TemporalRange {
    pub(crate) fn new(start_nanoseconds: i64, end_nanoseconds: i64) -> Option<Self> {
        (start_nanoseconds < end_nanoseconds).then_some(Self {
            start_nanoseconds,
            end_nanoseconds,
        })
    }

    pub(crate) fn contains(self, instant: positron_domain::time::UnixNanoseconds) -> bool {
        self.start_nanoseconds <= instant.value() && instant.value() < self.end_nanoseconds
    }

    pub(crate) fn duration(self) -> Option<u64> {
        u64::try_from(i128::from(self.end_nanoseconds) - i128::from(self.start_nanoseconds)).ok()
    }

    #[must_use]
    pub const fn start_nanoseconds(self) -> i64 {
        self.start_nanoseconds
    }

    #[must_use]
    pub const fn end_nanoseconds(self) -> i64 {
        self.end_nanoseconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FilterPredicate {
    BodyEquals(positron_domain::value::ValidatedAttributeValue),
    AttributeEquals(positron_signals::SchemaQuery),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProjectionColumn {
    Body,
    QueryTime,
    EventTime,
    IngestTime,
    CommitPosition,
    Attribute(positron_signals::SchemaPath),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AggregateSpec {
    group_by: Vec<ProjectionColumn>,
}

impl AggregateSpec {
    pub(crate) const fn count() -> Self {
        Self {
            group_by: Vec::new(),
        }
    }

    pub(crate) const fn count_by(group_by: Vec<ProjectionColumn>) -> Self {
        Self { group_by }
    }

    pub(crate) fn group_by(&self) -> &[ProjectionColumn] {
        &self.group_by
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OrderSpec {
    primary_direction: OrderDirection,
    commit_direction: OrderDirection,
}

impl OrderSpec {
    pub(crate) const fn new(
        primary_direction: OrderDirection,
        commit_direction: OrderDirection,
    ) -> Self {
        Self {
            primary_direction,
            commit_direction,
        }
    }

    pub(crate) const fn ascending(_axis: TemporalAxis) -> Self {
        Self {
            primary_direction: OrderDirection::Ascending,
            commit_direction: OrderDirection::Ascending,
        }
    }

    pub(crate) const fn primary_direction(self) -> OrderDirection {
        self.primary_direction
    }

    pub(crate) const fn commit_direction(self) -> OrderDirection {
        self.commit_direction
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalPlan {
    version: u8,
    axis: TemporalAxis,
    range: TemporalRange,
    limit: u16,
    filter: Option<FilterPredicate>,
    projection: Vec<ProjectionColumn>,
    aggregate: Option<AggregateSpec>,
    ordering: OrderSpec,
}

impl LogicalPlan {
    pub(crate) fn logs(axis: TemporalAxis, range: TemporalRange, limit: u16) -> Self {
        Self {
            version: 1,
            axis,
            range,
            limit,
            filter: None,
            projection: vec![ProjectionColumn::Body],
            aggregate: None,
            ordering: OrderSpec::ascending(axis),
        }
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn with_filter(mut self, filter: FilterPredicate) -> Self {
        self.filter = Some(filter);
        self
    }

    pub(crate) fn has_advanced_operators(&self) -> bool {
        self.filter.is_some()
            || self.projection != [ProjectionColumn::Body]
            || self.aggregate.is_some()
            || self.ordering != OrderSpec::ascending(self.axis)
    }

    pub(crate) fn filter(&self) -> Option<&FilterPredicate> {
        self.filter.as_ref()
    }

    pub(crate) fn schema_query(&self) -> Option<&positron_signals::SchemaQuery> {
        match self.filter.as_ref() {
            Some(FilterPredicate::AttributeEquals(query)) => Some(query),
            Some(FilterPredicate::BodyEquals(_)) | None => None,
        }
    }

    pub(crate) const fn requires_post_decode_predicate_fallback(&self) -> bool {
        self.filter.is_some()
    }

    pub(crate) fn with_projection(mut self, projection: Vec<ProjectionColumn>) -> Self {
        self.projection = projection;
        self
    }

    pub(crate) fn projection(&self) -> &[ProjectionColumn] {
        &self.projection
    }

    pub(crate) fn with_aggregate(mut self, aggregate: AggregateSpec) -> Self {
        self.aggregate = Some(aggregate);
        self
    }

    pub(crate) const fn aggregate(&self) -> Option<&AggregateSpec> {
        self.aggregate.as_ref()
    }

    pub(crate) fn with_ordering(mut self, ordering: OrderSpec) -> Self {
        self.ordering = ordering;
        self
    }

    pub(crate) const fn ordering(&self) -> OrderSpec {
        self.ordering
    }

    pub(crate) fn operator_count(&self) -> u64 {
        u64::from(self.projection != [ProjectionColumn::Body])
            + u64::from(self.aggregate.is_some())
            + u64::from(self.ordering != OrderSpec::ascending(self.axis))
    }

    pub(crate) const fn limit(&self) -> u16 {
        self.limit
    }

    #[must_use]
    pub const fn temporal_axis(&self) -> TemporalAxis {
        self.axis
    }

    #[must_use]
    pub const fn temporal_range(&self) -> TemporalRange {
        self.range
    }
}

pub struct PlannedQuery<'kernel> {
    pub(crate) context: AuthorizedContext,
    pub(crate) plan: LogicalPlan,
    pub(crate) budget: QueryBudget,
    pub(crate) _reservation: ResourceReservation<'kernel>,
    pub(crate) started_at: u64,
    pub(crate) last_observed_at: u64,
    pub(crate) cpu_work_units: u64,
    pub(crate) cancellation: crate::QueryCancellation,
}

impl PlannedQuery<'_> {
    #[must_use]
    pub fn logical_plan(&self) -> LogicalPlan {
        self.plan.clone()
    }

    /// Returns the query-scoped handle used to propagate disconnects and deadlines.
    #[must_use]
    pub fn cancellation(&self) -> crate::QueryCancellation {
        self.cancellation.clone()
    }
}
