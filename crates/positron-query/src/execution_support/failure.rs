use crate::{QueryFailure, QueryFailureCode};

pub(super) fn map_domain_value_failure(
    failure: positron_domain::outcome::DomainFailure,
) -> QueryFailure {
    if failure.code() == positron_domain::outcome::DomainFailureCode::AllocationUnavailable {
        QueryFailure::new(QueryFailureCode::ResourceExhausted)
    } else {
        QueryFailure::new(QueryFailureCode::Internal)
    }
}

pub(crate) fn map_ledger_failure(failure: positron_kernel::LedgerFailure) -> QueryFailure {
    match failure.code() {
        positron_kernel::LedgerFailureCode::SnapshotExpired => {
            QueryFailure::new(QueryFailureCode::SnapshotExpired)
        },
        positron_kernel::LedgerFailureCode::LimitExceeded => {
            QueryFailure::new(QueryFailureCode::InvalidBudget)
        },
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused => {
            QueryFailure::new(QueryFailureCode::ResourceAdmissionRefused)
        },
        _ => QueryFailure::new(QueryFailureCode::StoreUnavailable),
    }
}

pub(crate) fn map_store_failure(failure: positron_signals::LogStoreFailure) -> QueryFailure {
    QueryFailure::new(map_store_failure_code(failure.code()))
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
        _ => QueryFailureCode::StoreUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::map_store_failure_code;
    use crate::QueryFailureCode;

    #[test]
    fn storage_failures_preserve_resource_and_cancellation_truth() {
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
    }
}
