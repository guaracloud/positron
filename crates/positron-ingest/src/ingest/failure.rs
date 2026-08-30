use positron_kernel::{LedgerCompletionState, LedgerFailure, LedgerFailureCode};
use positron_signals::LogStoreFailureCode;

use super::{IngestFailureCode, IngestOutcome};

pub(crate) const fn classify_log_store_failure_code(code: LogStoreFailureCode) -> IngestOutcome {
    match code {
        LogStoreFailureCode::InvalidInput
        | LogStoreFailureCode::MalformedBlock
        | LogStoreFailureCode::PhysicalScopeMismatch => {
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
        },
        LogStoreFailureCode::LimitExceeded => {
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
        },
        LogStoreFailureCode::ResourceExhausted
        | LogStoreFailureCode::StorageExhausted
        | LogStoreFailureCode::BudgetExhausted
        | LogStoreFailureCode::ClockUnavailable
        | LogStoreFailureCode::ResourceAdmissionRefused => {
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
        },
        LogStoreFailureCode::IdempotencyConflict => {
            IngestOutcome::Permanent(IngestFailureCode::IdempotencyConflict)
        },
        LogStoreFailureCode::StorageUnavailable
        | LogStoreFailureCode::IntegrityCorruption
        | LogStoreFailureCode::AuthenticationFailed
        | LogStoreFailureCode::ConcurrentWriter
        | LogStoreFailureCode::UnsupportedFormat
        | LogStoreFailureCode::StaleGeneration
        | LogStoreFailureCode::RecoveryRequired
        | LogStoreFailureCode::SnapshotExpired
        | LogStoreFailureCode::StaleResumeMarker
        | LogStoreFailureCode::Internal => {
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable)
        },
        LogStoreFailureCode::Cancelled => IngestOutcome::Retryable(IngestFailureCode::Cancelled),
    }
}

pub(super) fn map_ledger_failure(failure: &LedgerFailure) -> IngestOutcome {
    classify_ledger_failure(failure.code(), failure.completion_state())
}

const fn classify_ledger_failure(
    failure_code: LedgerFailureCode,
    completion: LedgerCompletionState,
) -> IngestOutcome {
    let code = match failure_code {
        LedgerFailureCode::Cancelled => IngestFailureCode::Cancelled,
        LedgerFailureCode::IdempotencyConflict => IngestFailureCode::IdempotencyConflict,
        LedgerFailureCode::LimitExceeded => IngestFailureCode::ValueLimitExceeded,
        LedgerFailureCode::InvalidInput | LedgerFailureCode::PhysicalScopeMismatch => {
            IngestFailureCode::InvalidRecord
        },
        LedgerFailureCode::ResourceAdmissionRefused => IngestFailureCode::CapacityUnavailable,
        LedgerFailureCode::StorageUnavailable
        | LedgerFailureCode::StorageExhausted
        | LedgerFailureCode::IntegrityCorruption
        | LedgerFailureCode::AuthenticationFailed
        | LedgerFailureCode::ConcurrentWriter
        | LedgerFailureCode::UnsupportedFormat
        | LedgerFailureCode::StaleGeneration
        | LedgerFailureCode::SnapshotExpired
        | LedgerFailureCode::StaleResumeMarker
        | LedgerFailureCode::RecoveryRequired => IngestFailureCode::StorageUnavailable,
    };
    match completion {
        LedgerCompletionState::CommitAmbiguous => IngestOutcome::Ambiguous(code),
        LedgerCompletionState::RecoveryRequired => IngestOutcome::Retryable(code),
        LedgerCompletionState::RejectedBeforeMutation => match failure_code {
            LedgerFailureCode::InvalidInput
            | LedgerFailureCode::PhysicalScopeMismatch
            | LedgerFailureCode::LimitExceeded
            | LedgerFailureCode::IdempotencyConflict => IngestOutcome::Permanent(code),
            _ => IngestOutcome::Retryable(code),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{IngestFailureCode, IngestOutcome, classify_ledger_failure};
    use positron_kernel::{LedgerCompletionState as Completion, LedgerFailureCode as Ledger};

    #[test]
    fn ledger_codes_and_completion_states_remain_observable_at_ingest() {
        for (code, expected) in [
            (Ledger::Cancelled, IngestFailureCode::Cancelled),
            (
                Ledger::IdempotencyConflict,
                IngestFailureCode::IdempotencyConflict,
            ),
            (Ledger::LimitExceeded, IngestFailureCode::ValueLimitExceeded),
            (Ledger::InvalidInput, IngestFailureCode::InvalidRecord),
            (
                Ledger::PhysicalScopeMismatch,
                IngestFailureCode::InvalidRecord,
            ),
            (
                Ledger::ResourceAdmissionRefused,
                IngestFailureCode::CapacityUnavailable,
            ),
            (
                Ledger::StorageUnavailable,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::StorageExhausted,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::IntegrityCorruption,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::AuthenticationFailed,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::ConcurrentWriter,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::UnsupportedFormat,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::StaleGeneration,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::SnapshotExpired,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::StaleResumeMarker,
                IngestFailureCode::StorageUnavailable,
            ),
            (
                Ledger::RecoveryRequired,
                IngestFailureCode::StorageUnavailable,
            ),
        ] {
            assert_eq!(
                classify_ledger_failure(code, Completion::CommitAmbiguous),
                IngestOutcome::Ambiguous(expected)
            );
            assert_eq!(
                classify_ledger_failure(code, Completion::RecoveryRequired),
                IngestOutcome::Retryable(expected)
            );
            let rejected = classify_ledger_failure(code, Completion::RejectedBeforeMutation);
            if matches!(
                code,
                Ledger::InvalidInput
                    | Ledger::PhysicalScopeMismatch
                    | Ledger::LimitExceeded
                    | Ledger::IdempotencyConflict
            ) {
                assert_eq!(rejected, IngestOutcome::Permanent(expected));
            } else {
                assert_eq!(rejected, IngestOutcome::Retryable(expected));
            }
        }
    }
}
