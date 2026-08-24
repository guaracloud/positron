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
        positron_kernel::LedgerFailureCode::InvalidInput => QueryFailureCode::Internal,
        positron_kernel::LedgerFailureCode::PhysicalScopeMismatch
        | positron_kernel::LedgerFailureCode::IntegrityCorruption
        | positron_kernel::LedgerFailureCode::AuthenticationFailed
        | positron_kernel::LedgerFailureCode::UnsupportedFormat
        | positron_kernel::LedgerFailureCode::RecoveryRequired => {
            QueryFailureCode::MalformedPersistentData
        },
        positron_kernel::LedgerFailureCode::SnapshotExpired => QueryFailureCode::SnapshotExpired,
        positron_kernel::LedgerFailureCode::LimitExceeded => QueryFailureCode::InvalidBudget,
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused => {
            QueryFailureCode::ResourceAdmissionRefused
        },
        positron_kernel::LedgerFailureCode::StorageExhausted => QueryFailureCode::ResourceExhausted,
        positron_kernel::LedgerFailureCode::StorageUnavailable
        | positron_kernel::LedgerFailureCode::ConcurrentWriter
        | positron_kernel::LedgerFailureCode::IdempotencyConflict
        | positron_kernel::LedgerFailureCode::StaleGeneration => QueryFailureCode::StoreUnavailable,
        positron_kernel::LedgerFailureCode::Cancelled => QueryFailureCode::Cancelled,
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
        positron_signals::LogStoreFailureCode::InvalidInput => QueryFailureCode::InvalidBudget,
        positron_signals::LogStoreFailureCode::PhysicalScopeMismatch => {
            QueryFailureCode::MalformedPersistentData
        },
        positron_signals::LogStoreFailureCode::Kernel
        | positron_signals::LogStoreFailureCode::ClockUnavailable => {
            QueryFailureCode::StoreUnavailable
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
            QueryFailureCode::MalformedPersistentData
        );
        for (code, expected) in [
            (
                positron_kernel::LedgerFailureCode::InvalidInput,
                QueryFailureCode::Internal,
            ),
            (
                positron_kernel::LedgerFailureCode::PhysicalScopeMismatch,
                QueryFailureCode::MalformedPersistentData,
            ),
            (
                positron_kernel::LedgerFailureCode::AuthenticationFailed,
                QueryFailureCode::MalformedPersistentData,
            ),
            (
                positron_kernel::LedgerFailureCode::UnsupportedFormat,
                QueryFailureCode::MalformedPersistentData,
            ),
            (
                positron_kernel::LedgerFailureCode::StorageUnavailable,
                QueryFailureCode::StoreUnavailable,
            ),
            (
                positron_kernel::LedgerFailureCode::StorageExhausted,
                QueryFailureCode::ResourceExhausted,
            ),
            (
                positron_kernel::LedgerFailureCode::ConcurrentWriter,
                QueryFailureCode::StoreUnavailable,
            ),
            (
                positron_kernel::LedgerFailureCode::IdempotencyConflict,
                QueryFailureCode::StoreUnavailable,
            ),
            (
                positron_kernel::LedgerFailureCode::StaleGeneration,
                QueryFailureCode::StoreUnavailable,
            ),
            (
                positron_kernel::LedgerFailureCode::RecoveryRequired,
                QueryFailureCode::MalformedPersistentData,
            ),
            (
                positron_kernel::LedgerFailureCode::Cancelled,
                QueryFailureCode::Cancelled,
            ),
        ] {
            assert_eq!(map_ledger_failure_code(code), expected);
        }
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
            QueryFailureCode::MalformedPersistentData
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
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::InvalidInput),
            QueryFailureCode::InvalidBudget
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::PhysicalScopeMismatch),
            QueryFailureCode::MalformedPersistentData
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::Kernel),
            QueryFailureCode::StoreUnavailable
        );
        assert_eq!(
            map_store_failure_code(positron_signals::LogStoreFailureCode::ClockUnavailable),
            QueryFailureCode::StoreUnavailable
        );
    }

    #[test]
    fn scan_limit_failure_preserves_decoded_budget_dimension() {
        let failure = positron_signals::ScanLimit::new(usize::MAX)
            .expect_err("an unrepresentable scan limit must be rejected");
        let mapped = super::map_store_failure(failure);
        assert_eq!(mapped.code(), QueryFailureCode::BudgetExhausted);
        assert_eq!(
            mapped.limiting_budget(),
            Some(crate::QueryBudgetDimension::DecodedRecords)
        );
    }
}
