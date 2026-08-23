use crate::log_store::ScanObservationFailureCode;

/// Failures returned by bounded schema discovery and catalog operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaFailure {
    InvalidBudget,
    InvalidPath,
    PathTooLong,
    InvalidValue,
    LimitExceeded,
    AllocationUnavailable,
    MalformedCatalog,
    Observed(ScanObservationFailureCode),
}

impl std::fmt::Display for SchemaFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBudget => "invalid schema budget",
            Self::InvalidPath => "invalid schema path",
            Self::PathTooLong => "schema path too long",
            Self::InvalidValue => "invalid schema value",
            Self::LimitExceeded => "schema limit exceeded",
            Self::AllocationUnavailable => "schema allocation unavailable",
            Self::MalformedCatalog => "malformed schema catalog",
            Self::Observed(_) => "schema work observation failed",
        })
    }
}

impl std::error::Error for SchemaFailure {}
