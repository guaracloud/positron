use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::catalog::CatalogFailure;

/// The stable class of an active-segment operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerFailureCode {
    InvalidInput,
    PhysicalScopeMismatch,
    LimitExceeded,
    ResourceAdmissionRefused,
    StorageUnavailable,
    IntegrityCorruption,
    AuthenticationFailed,
    ConcurrentWriter,
    UnsupportedFormat,
    StorageExhausted,
    IdempotencyConflict,
    StaleGeneration,
    RecoveryRequired,
    Cancelled,
    SnapshotExpired,
    StaleResumeMarker,
}

/// Whether the failed call is safe to retry in place or requires recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerCompletionState {
    RejectedBeforeMutation,
    RecoveryRequired,
    CommitAmbiguous,
}

/// A bounded secret-free active-segment failure.
#[derive(Debug)]
pub struct LedgerFailure {
    code: LedgerFailureCode,
    completion: LedgerCompletionState,
}

impl LedgerFailure {
    pub(in crate::active_segment_ledger) const fn new(code: LedgerFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::RejectedBeforeMutation,
        }
    }

    pub(in crate::active_segment_ledger) const fn post_mutation(code: LedgerFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::RecoveryRequired,
        }
    }

    pub(in crate::active_segment_ledger) const fn ambiguous(code: LedgerFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::CommitAmbiguous,
        }
    }

    #[must_use]
    pub const fn code(&self) -> LedgerFailureCode {
        self.code
    }

    #[must_use]
    pub const fn completion_state(&self) -> LedgerCompletionState {
        self.completion
    }
}

impl Display for LedgerFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("active segment ledger operation failed")
    }
}

impl Error for LedgerFailure {}

impl From<CatalogFailure> for LedgerFailure {
    fn from(failure: CatalogFailure) -> Self {
        use crate::CatalogFailureCode as Code;
        let code = match failure.code() {
            Code::InvalidInput => LedgerFailureCode::InvalidInput,
            Code::IdempotencyConflict => LedgerFailureCode::IdempotencyConflict,
            Code::StaleGeneration => LedgerFailureCode::StaleGeneration,
            Code::LimitExceeded => LedgerFailureCode::LimitExceeded,
            Code::StorageUnavailable => LedgerFailureCode::StorageUnavailable,
            Code::IntegrityCorruption => LedgerFailureCode::IntegrityCorruption,
            Code::AuthenticationFailed => LedgerFailureCode::AuthenticationFailed,
            Code::ConcurrentWriter => LedgerFailureCode::ConcurrentWriter,
            Code::ResourceAdmissionRefused => LedgerFailureCode::ResourceAdmissionRefused,
            Code::UnsupportedFormat => LedgerFailureCode::UnsupportedFormat,
        };
        Self::new(code)
    }
}
