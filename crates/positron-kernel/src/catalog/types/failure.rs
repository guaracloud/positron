use std::error::Error;
use std::fmt::{Display, Formatter};

use super::CatalogGenerationId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogFailureCode {
    InvalidInput,
    LimitExceeded,
    StaleGeneration,
    IdempotencyConflict,
    StorageUnavailable,
    IntegrityCorruption,
    AuthenticationFailed,
    ConcurrentWriter,
    ResourceAdmissionRefused,
    UnsupportedFormat,
}

#[derive(Debug)]
pub struct CatalogFailure {
    pub(in crate::catalog) code: CatalogFailureCode,
    pub(in crate::catalog) current: Option<CatalogGenerationId>,
    pub(in crate::catalog) admission: Option<crate::AdmissionFailure>,
}

impl CatalogFailure {
    pub(crate) const fn new(code: CatalogFailureCode) -> Self {
        Self {
            code,
            current: None,
            admission: None,
        }
    }
    pub(in crate::catalog) const fn stale(current: CatalogGenerationId) -> Self {
        Self {
            code: CatalogFailureCode::StaleGeneration,
            current: Some(current),
            admission: None,
        }
    }
    pub(in crate::catalog) const fn admission(admission: crate::AdmissionFailure) -> Self {
        Self {
            code: CatalogFailureCode::ResourceAdmissionRefused,
            current: None,
            admission: Some(admission),
        }
    }
    #[must_use]
    pub const fn code(&self) -> CatalogFailureCode {
        self.code
    }
    #[must_use]
    pub const fn current_generation(&self) -> Option<CatalogGenerationId> {
        self.current
    }
    #[must_use]
    pub const fn admission_failure(&self) -> Option<crate::AdmissionFailure> {
        self.admission
    }
}

impl Display for CatalogFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("catalog operation failed")
    }
}

impl Error for CatalogFailure {}
