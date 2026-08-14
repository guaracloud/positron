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
        | LogStoreFailureCode::ClockUnavailable
        | LogStoreFailureCode::ResourceAdmissionRefused => {
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
        },
        LogStoreFailureCode::Kernel => {
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable)
        },
    }
}

pub(super) fn map_ledger_failure(failure: &LedgerFailure) -> IngestOutcome {
    let code = match failure.code() {
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
        | LedgerFailureCode::RecoveryRequired => IngestFailureCode::StorageUnavailable,
    };
    match failure.completion_state() {
        LedgerCompletionState::CommitAmbiguous => IngestOutcome::Ambiguous(code),
        LedgerCompletionState::RecoveryRequired => IngestOutcome::Retryable(code),
        LedgerCompletionState::RejectedBeforeMutation => match failure.code() {
            LedgerFailureCode::InvalidInput
            | LedgerFailureCode::PhysicalScopeMismatch
            | LedgerFailureCode::LimitExceeded
            | LedgerFailureCode::IdempotencyConflict => IngestOutcome::Permanent(code),
            _ => IngestOutcome::Retryable(code),
        },
    }
}
