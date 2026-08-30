use std::error::Error;
use std::fmt::{Display, Formatter};

use positron_domain::outcome::{DomainFailure, DomainFailureCode};
use positron_kernel::LedgerFailure;

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
}

impl LogStoreFailure {
    pub(super) const fn invalid_input() -> Self {
        Self {
            code: LogStoreFailureCode::InvalidInput,
        }
    }

    pub(super) const fn limit_exceeded() -> Self {
        Self {
            code: LogStoreFailureCode::LimitExceeded,
        }
    }

    pub(super) const fn malformed_block() -> Self {
        Self {
            code: LogStoreFailureCode::MalformedBlock,
        }
    }

    pub(super) const fn physical_scope_mismatch() -> Self {
        Self {
            code: LogStoreFailureCode::PhysicalScopeMismatch,
        }
    }

    pub(super) const fn resource_exhausted() -> Self {
        Self {
            code: LogStoreFailureCode::ResourceExhausted,
        }
    }

    pub(super) const fn clock_unavailable() -> Self {
        Self {
            code: LogStoreFailureCode::ClockUnavailable,
        }
    }

    pub(super) const fn resource_admission_refused() -> Self {
        Self {
            code: LogStoreFailureCode::ResourceAdmissionRefused,
        }
    }

    pub(super) const fn cancelled() -> Self {
        Self {
            code: LogStoreFailureCode::Cancelled,
        }
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
        Self { code }
    }

    pub(super) const fn domain(failure: DomainFailure) -> Self {
        Self {
            code: classify_domain_failure_code(failure.code()),
        }
    }

    pub(super) fn kernel(failure: LedgerFailure) -> Self {
        Self {
            code: classify_ledger_failure_code(failure.code()),
        }
    }

    #[must_use]
    pub const fn code(&self) -> LogStoreFailureCode {
        self.code
    }
}

pub(crate) const fn classify_ledger_failure_code(
    code: positron_kernel::LedgerFailureCode,
) -> LogStoreFailureCode {
    match code {
        positron_kernel::LedgerFailureCode::InvalidInput => LogStoreFailureCode::InvalidInput,
        positron_kernel::LedgerFailureCode::PhysicalScopeMismatch => {
            LogStoreFailureCode::PhysicalScopeMismatch
        },
        positron_kernel::LedgerFailureCode::LimitExceeded => LogStoreFailureCode::LimitExceeded,
        positron_kernel::LedgerFailureCode::ResourceAdmissionRefused => {
            LogStoreFailureCode::ResourceAdmissionRefused
        },
        positron_kernel::LedgerFailureCode::StorageUnavailable => {
            LogStoreFailureCode::StorageUnavailable
        },
        positron_kernel::LedgerFailureCode::IntegrityCorruption => {
            LogStoreFailureCode::IntegrityCorruption
        },
        positron_kernel::LedgerFailureCode::AuthenticationFailed => {
            LogStoreFailureCode::AuthenticationFailed
        },
        positron_kernel::LedgerFailureCode::ConcurrentWriter => {
            LogStoreFailureCode::ConcurrentWriter
        },
        positron_kernel::LedgerFailureCode::UnsupportedFormat => {
            LogStoreFailureCode::UnsupportedFormat
        },
        positron_kernel::LedgerFailureCode::StorageExhausted => {
            LogStoreFailureCode::StorageExhausted
        },
        positron_kernel::LedgerFailureCode::IdempotencyConflict => {
            LogStoreFailureCode::IdempotencyConflict
        },
        positron_kernel::LedgerFailureCode::StaleGeneration => LogStoreFailureCode::StaleGeneration,
        positron_kernel::LedgerFailureCode::RecoveryRequired => {
            LogStoreFailureCode::RecoveryRequired
        },
        positron_kernel::LedgerFailureCode::Cancelled => LogStoreFailureCode::Cancelled,
        positron_kernel::LedgerFailureCode::SnapshotExpired => LogStoreFailureCode::SnapshotExpired,
        positron_kernel::LedgerFailureCode::StaleResumeMarker => {
            LogStoreFailureCode::StaleResumeMarker
        },
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
    use super::{LogStoreFailure, LogStoreFailureCode, classify_ledger_failure_code};
    use crate::log_store::ScanObservationFailureCode;

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

    #[test]
    fn observation_failures_preserve_their_public_meaning() {
        for (observation, expected) in [
            (
                ScanObservationFailureCode::BudgetExhausted,
                LogStoreFailureCode::BudgetExhausted,
            ),
            (
                ScanObservationFailureCode::DecodedRecordsExhausted,
                LogStoreFailureCode::LimitExceeded,
            ),
            (
                ScanObservationFailureCode::Cancelled,
                LogStoreFailureCode::Cancelled,
            ),
            (
                ScanObservationFailureCode::ResourceExhausted,
                LogStoreFailureCode::ResourceExhausted,
            ),
            (
                ScanObservationFailureCode::Internal,
                LogStoreFailureCode::Internal,
            ),
        ] {
            assert_eq!(LogStoreFailure::observation(observation).code(), expected);
        }
    }

    #[test]
    fn every_kernel_failure_keeps_its_exact_log_store_class() {
        use positron_kernel::LedgerFailureCode as Kernel;

        for (kernel, expected) in [
            (Kernel::InvalidInput, LogStoreFailureCode::InvalidInput),
            (
                Kernel::PhysicalScopeMismatch,
                LogStoreFailureCode::PhysicalScopeMismatch,
            ),
            (Kernel::LimitExceeded, LogStoreFailureCode::LimitExceeded),
            (
                Kernel::ResourceAdmissionRefused,
                LogStoreFailureCode::ResourceAdmissionRefused,
            ),
            (
                Kernel::StorageUnavailable,
                LogStoreFailureCode::StorageUnavailable,
            ),
            (
                Kernel::IntegrityCorruption,
                LogStoreFailureCode::IntegrityCorruption,
            ),
            (
                Kernel::AuthenticationFailed,
                LogStoreFailureCode::AuthenticationFailed,
            ),
            (
                Kernel::ConcurrentWriter,
                LogStoreFailureCode::ConcurrentWriter,
            ),
            (
                Kernel::UnsupportedFormat,
                LogStoreFailureCode::UnsupportedFormat,
            ),
            (
                Kernel::StorageExhausted,
                LogStoreFailureCode::StorageExhausted,
            ),
            (
                Kernel::IdempotencyConflict,
                LogStoreFailureCode::IdempotencyConflict,
            ),
            (
                Kernel::StaleGeneration,
                LogStoreFailureCode::StaleGeneration,
            ),
            (
                Kernel::RecoveryRequired,
                LogStoreFailureCode::RecoveryRequired,
            ),
            (Kernel::Cancelled, LogStoreFailureCode::Cancelled),
            (
                Kernel::SnapshotExpired,
                LogStoreFailureCode::SnapshotExpired,
            ),
            (
                Kernel::StaleResumeMarker,
                LogStoreFailureCode::StaleResumeMarker,
            ),
        ] {
            assert_eq!(classify_ledger_failure_code(kernel), expected);
        }
    }
}
