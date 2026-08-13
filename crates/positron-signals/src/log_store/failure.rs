use std::error::Error;
use std::fmt::{Display, Formatter};

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

impl Display for LogStoreFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "log store failure: {:?}", self.code)
    }
}

impl Error for LogStoreFailure {}
