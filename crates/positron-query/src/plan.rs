use positron_governance::AuthorizedContext;
use positron_kernel::{ControlTokenProtector, ResourceReservation};
use std::fmt::Write as _;
use std::sync::Arc;

use crate::QueryBudget;
use crate::transform::BodyTransform;

const MAX_CANONICAL_PLAN_BYTES: usize = 65_536;

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
    BodyContains(crate::search::BoundedSubstring),
    BodyRegex(crate::search::BoundedRegex),
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
    transform: Option<BodyTransform>,
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
            transform: None,
        }
    }

    pub(crate) fn logs_with_memory(
        axis: TemporalAxis,
        range: TemporalRange,
        limit: u16,
        memory: &crate::planning_memory::PlanningMemory,
    ) -> Result<Self, crate::QueryFailure> {
        let plan_memory = memory.reserve(
            u64::try_from(std::mem::size_of::<Self>())
                .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::Internal))?,
        )?;
        let mut projection = crate::planning_memory::PlanningVec::with_capacity(memory, 1)?;
        projection.push(ProjectionColumn::Body)?;
        let plan = Self {
            version: 1,
            axis,
            range,
            limit,
            filter: None,
            projection: projection.into_vec(),
            aggregate: None,
            ordering: OrderSpec::ascending(axis),
            transform: None,
        };
        drop(plan_memory);
        Ok(plan)
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn with_filter(mut self, filter: FilterPredicate) -> Self {
        self.filter = Some(filter);
        self
    }

    pub(crate) fn with_transform(mut self, transform: BodyTransform) -> Self {
        self.transform = Some(transform);
        self
    }

    pub(crate) const fn transform(&self) -> Option<BodyTransform> {
        self.transform
    }

    pub(crate) fn has_advanced_operators(&self) -> bool {
        self.filter.is_some()
            || self.projection != [ProjectionColumn::Body]
            || self.aggregate.is_some()
            || self.ordering != OrderSpec::ascending(self.axis)
            || self.transform.is_some()
    }

    pub(crate) fn filter(&self) -> Option<&FilterPredicate> {
        self.filter.as_ref()
    }

    pub(crate) fn schema_query(&self) -> Option<&positron_signals::SchemaQuery> {
        match self.filter.as_ref() {
            Some(FilterPredicate::AttributeEquals(query)) => Some(query),
            Some(FilterPredicate::BodyEquals(_))
            | Some(FilterPredicate::BodyContains(_))
            | Some(FilterPredicate::BodyRegex(_))
            | None => None,
        }
    }

    pub(crate) fn search_memory_bytes(&self) -> u64 {
        match self.filter.as_ref() {
            Some(FilterPredicate::BodyContains(_)) => crate::search::text_memory_bytes(),
            Some(FilterPredicate::BodyRegex(regex)) => regex
                .memory_bytes()
                .max(crate::search::regex_peak_memory_bytes()),
            Some(FilterPredicate::BodyEquals(_))
            | Some(FilterPredicate::AttributeEquals(_))
            | None => 0,
        }
    }

    pub(crate) fn retained_memory_bytes(&self) -> Result<u64, crate::QueryFailure> {
        crate::planning_memory::retained_plan_bytes(self)
    }

    pub(crate) fn compile_search(&mut self) -> Result<(), crate::QueryFailure> {
        match self.filter.as_mut() {
            Some(FilterPredicate::BodyContains(substring)) => substring.compile(),
            Some(FilterPredicate::BodyRegex(regex)) => regex.compile(),
            Some(FilterPredicate::BodyEquals(_))
            | Some(FilterPredicate::AttributeEquals(_))
            | None => Ok(()),
        }
    }

    pub(crate) fn search_compile_work_units(&self) -> u64 {
        match self.filter.as_ref() {
            Some(FilterPredicate::BodyContains(substring)) => substring.compile_work_units(),
            Some(FilterPredicate::BodyRegex(regex)) => regex.compile_work_units(),
            Some(FilterPredicate::BodyEquals(_))
            | Some(FilterPredicate::AttributeEquals(_))
            | None => 0,
        }
    }

    pub(crate) fn text_search_candidate(
        &self,
    ) -> Result<Option<positron_signals::TextSearchCandidate>, crate::QueryFailure> {
        let candidate = match self.filter.as_ref() {
            Some(FilterPredicate::BodyContains(value)) => {
                positron_signals::TextSearchCandidate::literal(value.source())
            },
            Some(FilterPredicate::BodyRegex(regex)) => {
                positron_signals::TextSearchCandidate::any_of_bytes(regex.pruning_literals())
            },
            Some(FilterPredicate::BodyEquals(_))
            | Some(FilterPredicate::AttributeEquals(_))
            | None => return Ok(None),
        };
        candidate.map_err(|failure| match failure {
            positron_signals::SchemaFailure::AllocationUnavailable
            | positron_signals::SchemaFailure::LimitExceeded
            | positron_signals::SchemaFailure::Observed(_) => {
                crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted)
            },
            positron_signals::SchemaFailure::InvalidBudget
            | positron_signals::SchemaFailure::PathTooLong
            | positron_signals::SchemaFailure::InvalidPath
            | positron_signals::SchemaFailure::InvalidValue
            | positron_signals::SchemaFailure::MalformedCatalog => {
                crate::QueryFailure::new(crate::QueryFailureCode::UnsupportedQuery)
            },
        })
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
            + u64::from(self.transform.is_some())
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

    /// Computes the authenticated semantic plan identity shared by every
    /// frontend. Source spelling and frontend language are deliberately absent;
    /// only the parsed LogicalPlan's bounded operators and parameters enter
    /// this visitor.
    pub(crate) fn canonical_digest(
        &self,
        protector: &ControlTokenProtector<'_>,
        _memory: &crate::planning_memory::PlanningMemory,
    ) -> Result<[u8; 32], crate::QueryFailure> {
        let mut canonical = CanonicalBuffer::new();
        write!(
            canonical,
            "plan:v4;version={};axis={:?};range={}..{};limit={};filter=",
            self.version,
            self.axis,
            self.range.start_nanoseconds,
            self.range.end_nanoseconds,
            self.limit,
        )
        .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        match self.filter.as_ref() {
            Some(FilterPredicate::BodyEquals(value)) => write!(canonical, "body_equals:{value:?}"),
            Some(FilterPredicate::BodyContains(value)) => {
                write!(
                    canonical,
                    "body_contains:{}:{}",
                    value.source().len(),
                    value.source()
                )
            },
            Some(FilterPredicate::BodyRegex(value)) => {
                write!(
                    canonical,
                    "body_regex:{}:{}",
                    value.source().len(),
                    value.source()
                )
            },
            Some(FilterPredicate::AttributeEquals(query)) => {
                write!(canonical, "attribute_equals:{query:?}")
            },
            None => Ok(()),
        }
        .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        write!(
            canonical,
            ";projection={:?};aggregate={:?};ordering={:?};transform={:?}",
            self.projection, self.aggregate, self.ordering, self.transform,
        )
        .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::ResourceExhausted))?;
        protector
            .digest_query_plan(b"query-plan-canonical-v1", canonical.as_slice())
            .map_err(|_| crate::QueryFailure::new(crate::QueryFailureCode::Internal))
    }
}

struct CanonicalBuffer {
    bytes: [u8; MAX_CANONICAL_PLAN_BYTES],
    length: usize,
}

impl CanonicalBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_CANONICAL_PLAN_BYTES],
            length: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.length).unwrap_or(&[])
    }
}

impl std::fmt::Write for CanonicalBuffer {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let end = self
            .length
            .checked_add(value.len())
            .ok_or(std::fmt::Error)?;
        let target = self
            .bytes
            .get_mut(self.length..end)
            .ok_or(std::fmt::Error)?;
        target.copy_from_slice(value.as_bytes());
        self.length = end;
        Ok(())
    }
}

pub struct PlannedQuery<'kernel> {
    pub(crate) context: AuthorizedContext,
    pub(crate) plan: Arc<LogicalPlan>,
    pub(crate) source: Arc<[u8]>,
    pub(crate) language: crate::query_service::QueryLanguage,
    pub(crate) budget: QueryBudget,
    pub(crate) plan_digest: [u8; 32],
    pub(crate) _reservation: ResourceReservation<'kernel>,
    pub(crate) _planning_memory: crate::planning_memory::PlanningReservation,
    pub(crate) started_at: u64,
    pub(crate) last_observed_at: u64,
    pub(crate) cpu_work_units: u64,
    pub(crate) cancellation: crate::QueryCancellation,
}

impl PlannedQuery<'_> {
    #[must_use]
    pub fn logical_plan(&self) -> &LogicalPlan {
        self.plan.as_ref()
    }

    /// Returns the query-scoped handle used to propagate disconnects and deadlines.
    #[must_use]
    pub fn cancellation(&self) -> crate::QueryCancellation {
        self.cancellation.clone()
    }
}
