use positron_governance::AuthorizedContext;
use positron_kernel::ResourceReservation;

use crate::QueryBudget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemporalAxis {
    QueryTime,
    EventTime,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalPlan {
    axis: TemporalAxis,
    range: TemporalRange,
    limit: u16,
}

impl LogicalPlan {
    pub(crate) const fn logs(axis: TemporalAxis, range: TemporalRange, limit: u16) -> Self {
        Self { axis, range, limit }
    }

    pub(crate) const fn limit(self) -> u16 {
        self.limit
    }

    #[must_use]
    pub const fn temporal_axis(self) -> TemporalAxis {
        self.axis
    }

    #[must_use]
    pub const fn temporal_range(self) -> TemporalRange {
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
}

impl PlannedQuery<'_> {
    #[must_use]
    pub const fn logical_plan(&self) -> LogicalPlan {
        self.plan
    }
}
