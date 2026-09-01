use positron_kernel::{LedgerCompletionState, LedgerFailure, LedgerFailureCode};
use positron_signals::LogStoreFailureCode;

use super::{IngestFailureCode, IngestOutcome};

pub(crate) const fn classify_log_store_failure_code(code: LogStoreFailureCode) -> IngestOutcome {
    let failure_code = ingest_code_for_log_store(code);
    match code {
        LogStoreFailureCode::InvalidInput
        | LogStoreFailureCode::MalformedBlock
        | LogStoreFailureCode::PhysicalScopeMismatch
        | LogStoreFailureCode::LimitExceeded
        | LogStoreFailureCode::IdempotencyConflict => IngestOutcome::Permanent(failure_code),
        _ => IngestOutcome::Retryable(failure_code),
    }
}

const fn ingest_code_for_log_store(code: LogStoreFailureCode) -> IngestFailureCode {
    match code {
        LogStoreFailureCode::InvalidInput
        | LogStoreFailureCode::MalformedBlock
        | LogStoreFailureCode::PhysicalScopeMismatch => IngestFailureCode::InvalidRecord,
        LogStoreFailureCode::LimitExceeded => IngestFailureCode::ValueLimitExceeded,
        LogStoreFailureCode::ResourceExhausted
        | LogStoreFailureCode::StorageExhausted
        | LogStoreFailureCode::BudgetExhausted
        | LogStoreFailureCode::ClockUnavailable
        | LogStoreFailureCode::ResourceAdmissionRefused => IngestFailureCode::CapacityUnavailable,
        LogStoreFailureCode::IdempotencyConflict => IngestFailureCode::IdempotencyConflict,
        LogStoreFailureCode::StorageUnavailable
        | LogStoreFailureCode::IntegrityCorruption
        | LogStoreFailureCode::AuthenticationFailed
        | LogStoreFailureCode::ConcurrentWriter
        | LogStoreFailureCode::UnsupportedFormat
        | LogStoreFailureCode::StaleGeneration
        | LogStoreFailureCode::RecoveryRequired
        | LogStoreFailureCode::SnapshotExpired
        | LogStoreFailureCode::StaleResumeMarker
        | LogStoreFailureCode::Internal => IngestFailureCode::StorageUnavailable,
        LogStoreFailureCode::Cancelled => IngestFailureCode::Cancelled,
    }
}

pub(super) fn map_ledger_failure(failure: &LedgerFailure) -> IngestOutcome {
    classify_ledger_failure(failure.code(), failure.completion_state())
}

fn classify_ledger_failure(
    failure_code: LedgerFailureCode,
    completion: LedgerCompletionState,
) -> IngestOutcome {
    let code = match failure_code {
        LedgerFailureCode::StorageExhausted => IngestFailureCode::StorageUnavailable,
        other => ingest_code_for_log_store(LogStoreFailureCode::from(other)),
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
