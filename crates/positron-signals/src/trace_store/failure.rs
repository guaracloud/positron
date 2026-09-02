use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::outcome::{DomainFailure, DomainFailureCode};
use positron_kernel::{LedgerCompletionState, LedgerFailure, LedgerFailureCode as Kernel};

/// Stable failure class returned at the Trace Store interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceStoreFailureCode {
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

/// Redacted Trace Store failure containing no telemetry values.
#[derive(Debug)]
pub struct TraceStoreFailure {
    code: TraceStoreFailureCode,
    completion: LedgerCompletionState,
}

impl TraceStoreFailure {
    const fn rejected(code: TraceStoreFailureCode) -> Self {
        Self {
            code,
            completion: LedgerCompletionState::RejectedBeforeMutation,
        }
    }

    pub(super) const fn invalid_input() -> Self {
        Self::rejected(TraceStoreFailureCode::InvalidInput)
    }

    pub(super) const fn limit_exceeded() -> Self {
        Self::rejected(TraceStoreFailureCode::LimitExceeded)
    }

    pub(super) const fn malformed_block() -> Self {
        Self::rejected(TraceStoreFailureCode::MalformedBlock)
    }

    pub(super) const fn physical_scope_mismatch() -> Self {
        Self::rejected(TraceStoreFailureCode::PhysicalScopeMismatch)
    }

    pub(super) const fn resource_exhausted() -> Self {
        Self::rejected(TraceStoreFailureCode::ResourceExhausted)
    }

    #[cfg(any(test, fuzzing))]
    pub(super) const fn rejected_clock() -> Self {
        Self::rejected(TraceStoreFailureCode::ClockUnavailable)
    }

    pub(super) const fn resource_admission_refused() -> Self {
        Self::rejected(TraceStoreFailureCode::ResourceAdmissionRefused)
    }

    pub(super) const fn cancelled() -> Self {
        Self::rejected(TraceStoreFailureCode::Cancelled)
    }

    pub(super) const fn observation(code: crate::ScanObservationFailureCode) -> Self {
        let code = match code {
            crate::ScanObservationFailureCode::BudgetExhausted => {
                TraceStoreFailureCode::BudgetExhausted
            },
            crate::ScanObservationFailureCode::DecodedRecordsExhausted => {
                TraceStoreFailureCode::LimitExceeded
            },
            crate::ScanObservationFailureCode::Cancelled => TraceStoreFailureCode::Cancelled,
            crate::ScanObservationFailureCode::ResourceExhausted => {
                TraceStoreFailureCode::ResourceExhausted
            },
            crate::ScanObservationFailureCode::Internal => TraceStoreFailureCode::Internal,
        };
        Self::rejected(code)
    }

    pub(super) const fn domain(failure: DomainFailure) -> Self {
        Self::rejected(classify_domain_failure_code(failure.code()))
    }

    /// Maps a native validation failure at the authenticated block boundary.
    /// Value and structural failures are malformed durable data, while a
    /// bounded validation allocation refusal remains retryable capacity.
    pub(super) const fn validation(failure: DomainFailure) -> Self {
        Self::rejected(Self::validation_code(failure.code()))
    }

    #[cfg(test)]
    pub(super) const fn validation_for_test(code: DomainFailureCode) -> Self {
        Self::rejected(Self::validation_code(code))
    }

    const fn validation_code(code: DomainFailureCode) -> TraceStoreFailureCode {
        let mapped = classify_domain_failure_code(code);
        if matches!(mapped, TraceStoreFailureCode::ResourceExhausted) {
            TraceStoreFailureCode::ResourceExhausted
        } else {
            TraceStoreFailureCode::MalformedBlock
        }
    }

    pub(super) fn kernel(failure: LedgerFailure) -> Self {
        Self {
            code: failure.code().into(),
            completion: failure.completion_state(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> TraceStoreFailureCode {
        self.code
    }

    #[must_use]
    pub const fn completion_state(&self) -> LedgerCompletionState {
        self.completion
    }
}

impl From<Kernel> for TraceStoreFailureCode {
    fn from(code: Kernel) -> Self {
        classify_kernel_failure_code(code)
    }
}

pub(super) const fn classify_domain_failure_code(code: DomainFailureCode) -> TraceStoreFailureCode {
    match code {
        DomainFailureCode::AllocationUnavailable => TraceStoreFailureCode::ResourceExhausted,
        DomainFailureCode::ValueLimitExceeded => TraceStoreFailureCode::LimitExceeded,
        DomainFailureCode::InvalidIdentifier
        | DomainFailureCode::InvalidAttribution
        | DomainFailureCode::InvalidLifecycleTransition
        | DomainFailureCode::InvalidTimeAnnotation
        | DomainFailureCode::ArithmeticOverflow
        | DomainFailureCode::LimitExceedsSystem
        | DomainFailureCode::InvalidLimit => TraceStoreFailureCode::InvalidInput,
    }
}

pub(super) const fn classify_kernel_failure_code(code: Kernel) -> TraceStoreFailureCode {
    match code {
        Kernel::InvalidInput => TraceStoreFailureCode::InvalidInput,
        Kernel::PhysicalScopeMismatch => TraceStoreFailureCode::PhysicalScopeMismatch,
        Kernel::LimitExceeded => TraceStoreFailureCode::LimitExceeded,
        Kernel::ResourceAdmissionRefused => TraceStoreFailureCode::ResourceAdmissionRefused,
        Kernel::StorageUnavailable => TraceStoreFailureCode::StorageUnavailable,
        Kernel::IntegrityCorruption => TraceStoreFailureCode::IntegrityCorruption,
        Kernel::AuthenticationFailed => TraceStoreFailureCode::AuthenticationFailed,
        Kernel::ConcurrentWriter => TraceStoreFailureCode::ConcurrentWriter,
        Kernel::UnsupportedFormat => TraceStoreFailureCode::UnsupportedFormat,
        Kernel::StorageExhausted => TraceStoreFailureCode::StorageExhausted,
        Kernel::IdempotencyConflict => TraceStoreFailureCode::IdempotencyConflict,
        Kernel::StaleGeneration => TraceStoreFailureCode::StaleGeneration,
        Kernel::RecoveryRequired => TraceStoreFailureCode::RecoveryRequired,
        Kernel::Cancelled => TraceStoreFailureCode::Cancelled,
        Kernel::SnapshotExpired => TraceStoreFailureCode::SnapshotExpired,
        Kernel::StaleResumeMarker => TraceStoreFailureCode::StaleResumeMarker,
    }
}

impl Display for TraceStoreFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "trace store failure: {:?}", self.code)
    }
}

impl Error for TraceStoreFailure {}

impl From<positron_policy::PolicyProvenanceFailure> for TraceStoreFailure {
    fn from(_failure: positron_policy::PolicyProvenanceFailure) -> Self {
        Self::invalid_input()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TraceStoreFailure, TraceStoreFailureCode, classify_domain_failure_code,
        classify_kernel_failure_code,
    };
    use crate::ScanObservationFailureCode;
    use positron_domain::outcome::DomainFailureCode;
    use positron_kernel::LedgerCompletionState;
    use positron_kernel::LedgerFailureCode as Kernel;

    #[test]
    fn scan_observation_failures_keep_stable_redacted_codes() {
        let cases = [
            (
                ScanObservationFailureCode::BudgetExhausted,
                TraceStoreFailureCode::BudgetExhausted,
            ),
            (
                ScanObservationFailureCode::DecodedRecordsExhausted,
                TraceStoreFailureCode::LimitExceeded,
            ),
            (
                ScanObservationFailureCode::Cancelled,
                TraceStoreFailureCode::Cancelled,
            ),
            (
                ScanObservationFailureCode::ResourceExhausted,
                TraceStoreFailureCode::ResourceExhausted,
            ),
            (
                ScanObservationFailureCode::Internal,
                TraceStoreFailureCode::Internal,
            ),
        ];
        for (observation, expected) in cases {
            let failure = TraceStoreFailure::observation(observation);
            assert_eq!(failure.code(), expected);
            assert_eq!(
                failure.completion_state(),
                LedgerCompletionState::RejectedBeforeMutation
            );
        }
    }

    #[test]
    fn policy_failures_and_display_are_redacted() {
        let provenance_failure =
            positron_policy::PolicyProvenance::new(1, [0x70; 32], vec![String::new()])
                .expect_err("empty rule identity");
        let failure = TraceStoreFailure::from(provenance_failure);
        assert_eq!(failure.code(), TraceStoreFailureCode::InvalidInput);
        assert_eq!(failure.to_string(), "trace store failure: InvalidInput");

        assert_eq!(
            TraceStoreFailure::resource_exhausted().code(),
            TraceStoreFailureCode::ResourceExhausted
        );
        assert_eq!(
            TraceStoreFailure::rejected_clock().code(),
            TraceStoreFailureCode::ClockUnavailable
        );
        assert_eq!(
            TraceStoreFailure::resource_admission_refused().code(),
            TraceStoreFailureCode::ResourceAdmissionRefused
        );
    }

    #[test]
    fn domain_and_kernel_failure_codes_remain_closed_and_stable() {
        let domain_cases = [
            (
                DomainFailureCode::AllocationUnavailable,
                TraceStoreFailureCode::ResourceExhausted,
            ),
            (
                DomainFailureCode::ValueLimitExceeded,
                TraceStoreFailureCode::LimitExceeded,
            ),
            (
                DomainFailureCode::InvalidIdentifier,
                TraceStoreFailureCode::InvalidInput,
            ),
            (
                DomainFailureCode::InvalidAttribution,
                TraceStoreFailureCode::InvalidInput,
            ),
            (
                DomainFailureCode::InvalidLifecycleTransition,
                TraceStoreFailureCode::InvalidInput,
            ),
            (
                DomainFailureCode::InvalidTimeAnnotation,
                TraceStoreFailureCode::InvalidInput,
            ),
            (
                DomainFailureCode::ArithmeticOverflow,
                TraceStoreFailureCode::InvalidInput,
            ),
            (
                DomainFailureCode::LimitExceedsSystem,
                TraceStoreFailureCode::InvalidInput,
            ),
            (
                DomainFailureCode::InvalidLimit,
                TraceStoreFailureCode::InvalidInput,
            ),
        ];
        for (code, expected) in domain_cases {
            assert_eq!(classify_domain_failure_code(code), expected);
        }
        let allocation =
            TraceStoreFailure::validation_for_test(DomainFailureCode::AllocationUnavailable);
        assert_eq!(allocation.code(), TraceStoreFailureCode::ResourceExhausted);
        assert_eq!(
            allocation.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );
        let value_limit =
            TraceStoreFailure::validation_for_test(DomainFailureCode::ValueLimitExceeded);
        assert_eq!(value_limit.code(), TraceStoreFailureCode::MalformedBlock);
        assert_eq!(
            value_limit.completion_state(),
            LedgerCompletionState::RejectedBeforeMutation
        );

        let kernel_cases = [
            (Kernel::InvalidInput, TraceStoreFailureCode::InvalidInput),
            (
                Kernel::PhysicalScopeMismatch,
                TraceStoreFailureCode::PhysicalScopeMismatch,
            ),
            (Kernel::LimitExceeded, TraceStoreFailureCode::LimitExceeded),
            (
                Kernel::ResourceAdmissionRefused,
                TraceStoreFailureCode::ResourceAdmissionRefused,
            ),
            (
                Kernel::StorageUnavailable,
                TraceStoreFailureCode::StorageUnavailable,
            ),
            (
                Kernel::IntegrityCorruption,
                TraceStoreFailureCode::IntegrityCorruption,
            ),
            (
                Kernel::AuthenticationFailed,
                TraceStoreFailureCode::AuthenticationFailed,
            ),
            (
                Kernel::ConcurrentWriter,
                TraceStoreFailureCode::ConcurrentWriter,
            ),
            (
                Kernel::UnsupportedFormat,
                TraceStoreFailureCode::UnsupportedFormat,
            ),
            (
                Kernel::StorageExhausted,
                TraceStoreFailureCode::StorageExhausted,
            ),
            (
                Kernel::IdempotencyConflict,
                TraceStoreFailureCode::IdempotencyConflict,
            ),
            (
                Kernel::StaleGeneration,
                TraceStoreFailureCode::StaleGeneration,
            ),
            (
                Kernel::RecoveryRequired,
                TraceStoreFailureCode::RecoveryRequired,
            ),
            (Kernel::Cancelled, TraceStoreFailureCode::Cancelled),
            (
                Kernel::SnapshotExpired,
                TraceStoreFailureCode::SnapshotExpired,
            ),
            (
                Kernel::StaleResumeMarker,
                TraceStoreFailureCode::StaleResumeMarker,
            ),
        ];
        for (code, expected) in kernel_cases {
            assert_eq!(classify_kernel_failure_code(code), expected);
            let converted: TraceStoreFailureCode = code.into();
            assert_eq!(converted, expected);
        }
    }
}
