use std::fmt::{Display, Formatter};

use crate::QueryBudgetDimension;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryFailureCode {
    Unauthorized,
    InvalidBudget,
    BudgetExhausted,
    InvalidCursor,
    SnapshotExpired,
    AuthorizationChanged,
    Cancelled,
    ResourceAdmissionRefused,
    ResourceExhausted,
    UnsupportedQuery,
    StoreUnavailable,
    MalformedPersistentData,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryFailure {
    code: QueryFailureCode,
    limiting_budget: Option<QueryBudgetDimension>,
}

impl QueryFailure {
    pub(crate) const fn new(code: QueryFailureCode) -> Self {
        Self {
            code,
            limiting_budget: None,
        }
    }

    pub(crate) const fn budget_exhausted(dimension: QueryBudgetDimension) -> Self {
        Self::for_budget(QueryFailureCode::BudgetExhausted, dimension)
    }

    pub(crate) const fn for_budget(
        code: QueryFailureCode,
        dimension: QueryBudgetDimension,
    ) -> Self {
        Self {
            code,
            limiting_budget: Some(dimension),
        }
    }

    #[must_use]
    pub const fn code(&self) -> QueryFailureCode {
        self.code
    }

    #[must_use]
    /// Returns the effective budget limit associated with this failure.
    ///
    /// Invalid request budgets may identify their limiting dimension without
    /// being runtime `BudgetExhausted` failures.
    pub const fn limiting_budget(&self) -> Option<QueryBudgetDimension> {
        self.limiting_budget
    }
}

impl Display for QueryFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("query request failed")
    }
}

impl std::error::Error for QueryFailure {}
