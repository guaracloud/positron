use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::outcome::{DomainFailure, DomainFailureCode};
use positron_kernel::{LedgerCompletionState, LedgerFailure, LedgerFailureCode as Kernel};

/// Stable failure class returned at the Log Store interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogStoreFailureCode {
    InvalidInput,
    LimitExceeded,
    MalformedBlock,
    PhysicalScopeMismatch,
    StorageUnavailable,
    IntegrityCorruption,
    AuthenticationFailed,
    ConcurrentWriter,
    UnsupportedFormat,
    StorageExhausted,
    IdempotencyConflict,
    StaleGeneration,
    RecoveryRequired,
    SnapshotExpired,
    StaleResumeMarker,
    ResourceExhausted,
    ClockUnavailable,
    ResourceAdmissionRefused,
    Cancelled,
    BudgetExhausted,
    Internal,
}

/// Redacted Log Store failure that never contains telemetry values.
#[derive(Debug)]
pub struct LogStoreFailure {
    code: LogStoreFailureCode,
    completion: LedgerCompletionState,
}

impl LogStoreFailure {
    const fn rejected(code: LogStoreFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::RejectedBeforeMutation,
        }
    }

    pub(super) const fn invalid_input() -> Self {
        Self::rejected(LogStoreFailureCode::InvalidInput)
    }

    pub(super) const fn limit_exceeded() -> Self {
        Self::rejected(LogStoreFailureCode::LimitExceeded)
    }

    pub(super) const fn malformed_block() -> Self {
        Self::rejected(LogStoreFailureCode::MalformedBlock)
    }

    pub(super) const fn physical_scope_mismatch() -> Self {
        Self::rejected(LogStoreFailureCode::PhysicalScopeMismatch)
    }

    pub(super) const fn resource_exhausted() -> Self {
        Self::rejected(LogStoreFailureCode::ResourceExhausted)
    }

    #[cfg(any(test, fuzzing))]
    pub(super) const fn clock_unavailable() -> Self {
        Self::rejected(LogStoreFailureCode::ClockUnavailable)
    }

    pub(super) const fn resource_admission_refused() -> Self {
        Self::rejected(LogStoreFailureCode::ResourceAdmissionRefused)
    }

    pub(super) const fn cancelled() -> Self {
        Self::rejected(LogStoreFailureCode::Cancelled)
    }

    pub(super) const fn observation(code: super::ScanObservationFailureCode) -> Self {
        let code = match code {
            super::ScanObservationFailureCode::BudgetExhausted => {
                LogStoreFailureCode::BudgetExhausted
            },
            super::ScanObservationFailureCode::DecodedRecordsExhausted => {
                LogStoreFailureCode::LimitExceeded
            },
            super::ScanObservationFailureCode::Cancelled => LogStoreFailureCode::Cancelled,
            super::ScanObservationFailureCode::ResourceExhausted => {
                LogStoreFailureCode::ResourceExhausted
            },
            super::ScanObservationFailureCode::Internal => LogStoreFailureCode::Internal,
        };
        Self::rejected(code)
    }

    pub(super) const fn domain(failure: DomainFailure) -> Self {
        Self::rejected(classify_domain_failure_code(failure.code()))
    }

    pub(super) fn kernel(failure: LedgerFailure) -> Self {
        Self {
            code: failure.code().into(),
            completion: failure.completion_state(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> LogStoreFailureCode {
        self.code
    }

    #[must_use]
    pub const fn completion_state(&self) -> LedgerCompletionState {
        self.completion
    }
}

impl From<positron_kernel::LedgerFailureCode> for LogStoreFailureCode {
    fn from(code: positron_kernel::LedgerFailureCode) -> Self {
        match code {
            Kernel::InvalidInput => LogStoreFailureCode::InvalidInput,
            Kernel::PhysicalScopeMismatch => LogStoreFailureCode::PhysicalScopeMismatch,
            Kernel::LimitExceeded => LogStoreFailureCode::LimitExceeded,
            Kernel::ResourceAdmissionRefused => LogStoreFailureCode::ResourceAdmissionRefused,
            Kernel::StorageUnavailable => LogStoreFailureCode::StorageUnavailable,
            Kernel::IntegrityCorruption => LogStoreFailureCode::IntegrityCorruption,
            Kernel::AuthenticationFailed => LogStoreFailureCode::AuthenticationFailed,
            Kernel::ConcurrentWriter => LogStoreFailureCode::ConcurrentWriter,
            Kernel::UnsupportedFormat => LogStoreFailureCode::UnsupportedFormat,
            Kernel::StorageExhausted => LogStoreFailureCode::StorageExhausted,
            Kernel::IdempotencyConflict => LogStoreFailureCode::IdempotencyConflict,
            Kernel::StaleGeneration => LogStoreFailureCode::StaleGeneration,
            Kernel::RecoveryRequired => LogStoreFailureCode::RecoveryRequired,
            Kernel::Cancelled => LogStoreFailureCode::Cancelled,
            Kernel::SnapshotExpired => LogStoreFailureCode::SnapshotExpired,
            Kernel::StaleResumeMarker => LogStoreFailureCode::StaleResumeMarker,
        }
    }
}

pub(crate) const fn classify_domain_failure_code(code: DomainFailureCode) -> LogStoreFailureCode {
    match code {
        DomainFailureCode::AllocationUnavailable => LogStoreFailureCode::ResourceExhausted,
        DomainFailureCode::ValueLimitExceeded => LogStoreFailureCode::LimitExceeded,
        DomainFailureCode::InvalidIdentifier
        | DomainFailureCode::InvalidAttribution
        | DomainFailureCode::InvalidLifecycleTransition
        | DomainFailureCode::InvalidTimeAnnotation
        | DomainFailureCode::ArithmeticOverflow
        | DomainFailureCode::LimitExceedsSystem
        | DomainFailureCode::InvalidLimit => LogStoreFailureCode::InvalidInput,
    }
}

impl Display for LogStoreFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "log store failure: {:?}", self.code)
    }
}

impl Error for LogStoreFailure {}

impl From<positron_policy::PolicyProvenanceFailure> for LogStoreFailure {
    fn from(_failure: positron_policy::PolicyProvenanceFailure) -> Self {
        Self::invalid_input()
    }
}

#[cfg(test)]
mod tests {
    use super::{LogStoreFailure, LogStoreFailureCode};

    #[test]
    fn invalid_policy_provenance_maps_to_the_log_store_input_class() {
        let provenance_failure =
            positron_policy::PolicyProvenance::new(1, [0x70; 32], vec![String::new()])
                .expect_err("empty rule identity");
        let failure = LogStoreFailure::from(provenance_failure);
        assert_eq!(failure.code(), LogStoreFailureCode::InvalidInput);
    }

    #[test]
    fn infrastructure_failures_keep_distinct_redacted_public_codes() {
        let resource = LogStoreFailure::resource_exhausted();
        assert_eq!(resource.code(), LogStoreFailureCode::ResourceExhausted);
        assert_eq!(resource.to_string(), "log store failure: ResourceExhausted");

        let clock = LogStoreFailure::clock_unavailable();
        assert_eq!(clock.code(), LogStoreFailureCode::ClockUnavailable);
        assert_eq!(clock.to_string(), "log store failure: ClockUnavailable");

        let ledger = positron_kernel::SnapshotLeaseId::new([0; 16])
            .expect_err("zero lease identity must remain invalid");
        let kernel = LogStoreFailure::kernel(ledger);
        assert_eq!(kernel.code(), LogStoreFailureCode::InvalidInput);
        assert_eq!(kernel.to_string(), "log store failure: InvalidInput");
    }
}
