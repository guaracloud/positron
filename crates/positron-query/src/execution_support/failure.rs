use crate::{QueryBudgetDimension, QueryFailure, QueryFailureCode};
use positron_kernel::LedgerFailureCode as Ledger;
use positron_signals::{LogStoreFailureCode as Store, LogStoreFailureCode};

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

fn map_ledger_failure_code(code: positron_kernel::LedgerFailureCode) -> QueryFailureCode {
    match code {
        Ledger::InvalidInput => QueryFailureCode::Internal,
        Ledger::LimitExceeded => QueryFailureCode::InvalidBudget,
        other => map_store_failure_code(LogStoreFailureCode::from(other)),
    }
}

pub(crate) fn map_store_failure(failure: positron_signals::LogStoreFailure) -> QueryFailure {
    match failure.code() {
        LogStoreFailureCode::LimitExceeded => {
            QueryFailure::budget_exhausted(QueryBudgetDimension::DecodedRecords)
        },
        LogStoreFailureCode::BudgetExhausted => {
            QueryFailure::budget_exhausted(QueryBudgetDimension::CpuWorkUnits)
        },
        code => QueryFailure::new(map_store_failure_code(code)),
    }
}

const fn map_store_failure_code(code: positron_signals::LogStoreFailureCode) -> QueryFailureCode {
    match code {
        Store::MalformedBlock => QueryFailureCode::MalformedPersistentData,
        Store::InvalidInput => QueryFailureCode::InvalidBudget,
        Store::PhysicalScopeMismatch => QueryFailureCode::MalformedPersistentData,
        Store::StorageUnavailable
        | Store::ConcurrentWriter
        | Store::IdempotencyConflict
        | Store::StaleGeneration
        | Store::ClockUnavailable => QueryFailureCode::StoreUnavailable,
        Store::IntegrityCorruption
        | Store::AuthenticationFailed
        | Store::UnsupportedFormat
        | Store::RecoveryRequired => QueryFailureCode::MalformedPersistentData,
        Store::SnapshotExpired => QueryFailureCode::SnapshotExpired,
        Store::StaleResumeMarker => QueryFailureCode::InvalidCursor,
        Store::StorageExhausted => QueryFailureCode::ResourceExhausted,
        Store::ResourceAdmissionRefused => QueryFailureCode::ResourceAdmissionRefused,
        Store::LimitExceeded => QueryFailureCode::BudgetExhausted,
        Store::ResourceExhausted => QueryFailureCode::ResourceExhausted,
        Store::Cancelled => QueryFailureCode::Cancelled,
        Store::BudgetExhausted => QueryFailureCode::BudgetExhausted,
        Store::Internal => QueryFailureCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use crate::QueryFailureCode;

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
