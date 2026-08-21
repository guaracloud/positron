use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};

pub(crate) fn map_domain_value_failure(
    failure: positron_domain::outcome::DomainFailure,
) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        QueryFailure::new(QueryFailureCode::Internal)
    }
}

pub(crate) fn map_ledger_failure(failure: positron_kernel::LedgerFailure) -> QueryFailure {
    QueryFailure::new(map_ledger_failure_code(failure.code()))
}

const fn map_ledger_failure_code(code: positron_kernel::LedgerFailureCode) -> QueryFailureCode {
    match code {
        positron_kernel::LedgerFailureCode::SnapshotExpired => QueryFailureCode::SnapshotExpired,
        positron_kernel::LedgerFailureCode::LimitExceeded => QueryFailureCode::InvalidBudget,
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused => {
            QueryFailureCode::ResourceAdmissionRefused
        },
        _ => QueryFailureCode::StoreUnavailable,
    }
}

pub(crate) fn map_store_failure(failure: positron_signals::LogStoreFailure) -> QueryFailure {
    match failure.code() {
        positron_signals::LogStoreFailureCode::LimitExceeded => {
            QueryFailure::budget_exhausted(QueryBudgetDimension::DecodedRecords)
        },
        positron_signals::LogStoreFailureCode::BudgetExhausted => {
            QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits)
        },
        code => QueryFailure::new(map_store_failure_code(code)),
    }
}

const fn map_store_failure_code(code: positron_signals::LogStoreFailureCode) -> QueryFailureCode {
    match code {
        positron_signals::LogStoreFailureCode::MalformedBlock => {
            QueryFailureCode::MalformedPersistentData
        },
        positron_signals::LogStoreFailureCode::ResourceAdmissionRefused => {
            QueryFailureCode::ResourceAdmissionRefused
        },
        positron_signals::LogStoreFailureCode::LimitExceeded => QueryFailureCode::BudgetExhausted,
        positron_signals::LogStoreFailureCode::ResourceExhausted => {
            QueryFailureCode::ResourceExhausted
        },
        positron_signals::LogStoreFailureCode::Cancelled => QueryFailureCode::Cancelled,
        positron_signals::LogStoreFailureCode::BudgetExhausted => QueryFailureCode::BudgetExhausted,
        positron_signals::LogStoreFailureCode::Internal => QueryFailureCode::Internal,
        _ => QueryFailureCode::StoreUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::{map_ledger_failure_code, map_store_failure_code};
    use crate::QueryFailureCode;

    #[test]
    fn storage_failures_preserve_resource_and_cancellation_truth() {
        assert_eq!(
            map_ledger_failure_code(positron_kernel::LedgerFailureCode::SnapshotExpired),
            QueryFailureCode::SnapshotExpired
        );
        assert_eq!(
            map_ledger_failure_code(positron_kernel::LedgerFailureCode::LimitExceeded),
            QueryFailureCode::InvalidBudget
        );
        assert_eq!(
            map_ledger_failure_code(positron_kernel::LedgerFailureCode::ResourceAdmissionRefused),
            QueryFailureCode::ResourceAdmissionRefused
        );
        assert_eq!(
            map_ledger_failure_code(positron_kernel::LedgerFailureCode::IntegrityCorruption),
            QueryFailureCode::StoreUnavailable
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::ResourceExhausted),
            QueryFailureCode::ResourceExhausted
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::LimitExceeded),
            QueryFailureCode::BudgetExhausted
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::Cancelled),
            QueryFailureCode::Cancelled
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::PhysicalScopeMismatch),
            QueryFailureCode::StoreUnavailable
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::MalformedBlock),
            QueryFailureCode::MalformedPersistentData
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::ResourceAdmissionRefused),
            QueryFailureCode::ResourceAdmissionRefused
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::BudgetExhausted),
            QueryFailureCode::BudgetExhausted
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::Internal),
            QueryFailureCode::Internal
        );
    }
}
