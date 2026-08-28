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

pub(crate) fn stronger_failure(left: QueryFailure, right: QueryFailure) -> QueryFailure {
    if failure_rank(right.code) > failure_rank(left.code) {
        right
    } else {
        left
    }
}

pub(crate) fn retain_stronger(current: &mut Option<QueryFailure>, candidate: QueryFailure) {
    match current.take() {
        Some(existing) => *current = Some(stronger_failure(existing, candidate)),
        None => *current = Some(candidate),
    }
}

pub(crate) fn retain_internal(current: &mut Option<QueryFailure>) {
    retain_stronger(current, QueryFailure::new(QueryFailureCode::Internal));
}

fn failure_rank(code: QueryFailureCode) -> u8 {
    match code {
        QueryFailureCode::Internal | QueryFailureCode::MalformedPersistentData => 4,
        QueryFailureCode::StoreUnavailable | QueryFailureCode::AuthorizationChanged => 3,
        QueryFailureCode::ResourceExhausted | QueryFailureCode::BudgetExhausted => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{QueryFailure, QueryFailureCode, retain_internal, stronger_failure};

    #[test]
    fn strongest_failure_preserves_primary_on_ties_and_prefers_integrity() {
        assert_eq!(
            stronger_failure(
                QueryFailure::new(QueryFailureCode::StoreUnavailable),
                QueryFailure::new(QueryFailureCode::BudgetExhausted),
            )
            .code(),
            QueryFailureCode::StoreUnavailable
        );
        assert_eq!(
            stronger_failure(
                QueryFailure::new(QueryFailureCode::StoreUnavailable),
                QueryFailure::new(QueryFailureCode::Internal),
            )
            .code(),
            QueryFailureCode::Internal
        );
        assert_eq!(
            stronger_failure(
                QueryFailure::new(QueryFailureCode::Internal),
                QueryFailure::new(QueryFailureCode::StoreUnavailable),
            )
            .code(),
            QueryFailureCode::Internal
        );
    }

    #[test]
    fn retain_internal_preserves_the_strongest_failure() {
        let mut failure = Some(QueryFailure::new(QueryFailureCode::StoreUnavailable));
        retain_internal(&mut failure);
        assert_eq!(
            failure.as_ref().map(QueryFailure::code),
            Some(QueryFailureCode::Internal)
        );
    }
}
