use std::fmt::{Display, Formatter};

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
    UnsupportedQuery,
    StoreUnavailable,
    MalformedPersistentData,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryFailure {
    code: QueryFailureCode,
}

impl QueryFailure {
    pub(crate) const fn new(code: QueryFailureCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> QueryFailureCode {
        self.code
    }
}

impl Display for QueryFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("query request failed")
    }
}

impl std::error::Error for QueryFailure {}
