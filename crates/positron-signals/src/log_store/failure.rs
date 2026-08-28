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
    Kernel,
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

    pub(super) fn kernel(_failure: LedgerFailure) -> Self {
        Self {
            code: LogStoreFailureCode::Kernel,
        }
    }

    #[must_use]
    pub const fn code(&self) -> LogStoreFailureCode {
        self.code
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

#[cfg(test)]
mod tests {
    use super::{LogStoreFailure, LogStoreFailureCode};
    use crate::log_store::ScanObservationFailureCode;

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
        assert_eq!(kernel.code(), LogStoreFailureCode::Kernel);
        assert_eq!(kernel.to_string(), "log store failure: Kernel");
    }

    #[test]
    fn decoded_record_budget_observation_maps_to_public_limit_failure() {
        let failure =
            LogStoreFailure::observation(ScanObservationFailureCode::DecodedRecordsExhausted);
        assert_eq!(failure.code(), LogStoreFailureCode::LimitExceeded);
    }
}
