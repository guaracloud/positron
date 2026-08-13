use positron_governance::AuthorizedContext;
use positron_kernel::ResourceReservation;

use crate::QueryBudget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalPlan {
    limit: u16,
}

impl LogicalPlan {
    pub(crate) const fn logs(limit: u16) -> Self {
        Self { limit }
    }

    pub(crate) const fn limit(self) -> u16 {
        self.limit
    }
}

pub struct PlannedQuery<'kernel> {
    pub(crate) context: AuthorizedContext,
    pub(crate) plan: LogicalPlan,
    pub(crate) budget: QueryBudget,
    pub(crate) _reservation: ResourceReservation<'kernel>,
}

impl PlannedQuery<'_> {
    #[must_use]
    pub const fn logical_plan(&self) -> LogicalPlan {
        self.plan
    }
}
