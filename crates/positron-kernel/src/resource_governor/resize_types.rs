//! Stable public outcomes for runtime reservation correction.

use std::error::Error;
use std::fmt::{Display, Formatter};

use super::accounting::ChargeOwner;
use super::claim::WorkClass;
use super::failure::{
    AdmissionEvidence, AdmissionFailure, AdmissionFailureCode, AdmissionRetry, DiskPressureState,
    LimitingScope,
};
use super::model::{ResourceAmounts, ResourceDimension};

/// Result of a successful atomic replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResizeOutcome {
    pub(super) released: ResourceAmounts,
    pub(super) added: ResourceAmounts,
}

impl ResizeOutcome {
    #[must_use]
    pub const fn released(self) -> ResourceAmounts {
        self.released
    }

    #[must_use]
    pub const fn added(self) -> ResourceAmounts {
        self.added
    }
}

/// Stable resize failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResizeFailureCode {
    InvalidRequest,
    InactiveReservation,
    AdmissionRefused,
    InternalFenced,
}

/// What happened to capacity owned before a failed resize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingCapacityDisposition {
    CancelledBeforeLimit,
    CapacityRetained,
    NoActiveCapacity,
}

/// Typed, bounded evidence for an incomplete resize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResizeFailure {
    pub(super) code: ResizeFailureCode,
    admission_code: Option<AdmissionFailureCode>,
    retry: AdmissionRetry,
    scope: LimitingScope,
    pressure: DiskPressureState,
    class: WorkClass,
    disposition: ExistingCapacityDisposition,
    dimension: Option<ResourceDimension>,
    allowed: u64,
    in_use: u64,
    requested: u64,
}

impl ResizeFailure {
    #[must_use]
    pub const fn code(self) -> ResizeFailureCode {
        self.code
    }

    #[must_use]
    pub const fn admission_code(self) -> Option<AdmissionFailureCode> {
        self.admission_code
    }

    #[must_use]
    pub const fn retry(self) -> AdmissionRetry {
        self.retry
    }

    #[must_use]
    pub const fn limiting_scope(self) -> LimitingScope {
        self.scope
    }

    #[must_use]
    pub const fn pressure_state(self) -> DiskPressureState {
        self.pressure
    }

    #[must_use]
    pub const fn work_class(self) -> WorkClass {
        self.class
    }

    #[must_use]
    pub const fn existing_capacity(self) -> ExistingCapacityDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn limiting_dimension(self) -> Option<ResourceDimension> {
        self.dimension
    }

    #[must_use]
    pub const fn allowed(self) -> u64 {
        self.allowed
    }

    #[must_use]
    pub const fn in_use(self) -> u64 {
        self.in_use
    }

    #[must_use]
    pub const fn requested(self) -> u64 {
        self.requested
    }

    pub(super) const fn invalid(class: WorkClass, pressure: DiskPressureState) -> Self {
        Self {
            code: ResizeFailureCode::InvalidRequest,
            admission_code: None,
            retry: AdmissionRetry::Never,
            scope: LimitingScope::Policy,
            pressure,
            class,
            disposition: ExistingCapacityDisposition::CapacityRetained,
            dimension: None,
            allowed: 0,
            in_use: 0,
            requested: 0,
        }
    }

    pub(super) const fn inactive(class: WorkClass, pressure: DiskPressureState) -> Self {
        Self {
            code: ResizeFailureCode::InactiveReservation,
            admission_code: None,
            retry: AdmissionRetry::Never,
            scope: LimitingScope::Internal,
            pressure,
            class,
            disposition: ExistingCapacityDisposition::NoActiveCapacity,
            dimension: None,
            allowed: 0,
            in_use: 0,
            requested: 0,
        }
    }

    pub(super) fn admission(
        failure: AdmissionFailure,
        disposition: ExistingCapacityDisposition,
    ) -> Self {
        let code = if failure.code() == AdmissionFailureCode::InternalFenced {
            ResizeFailureCode::InternalFenced
        } else {
            ResizeFailureCode::AdmissionRefused
        };
        Self {
            code,
            admission_code: Some(failure.code()),
            retry: failure.retry(),
            scope: failure.limiting_scope(),
            pressure: failure.pressure_state(),
            class: failure.work_class(),
            disposition,
            dimension: failure.limiting_dimension(),
            allowed: failure.allowed(),
            in_use: failure.in_use(),
            requested: failure.requested(),
        }
    }

    pub(super) const fn admission_failure(self) -> Option<AdmissionFailure> {
        let Some(code) = self.admission_code else {
            return None;
        };
        Some(AdmissionFailure::new(AdmissionEvidence {
            code,
            retry: self.retry,
            scope: self.scope,
            class: self.class,
            pressure: self.pressure,
            dimension: self.dimension,
            allowed: self.allowed,
            in_use: self.in_use,
            requested: self.requested,
        }))
    }
}

impl Display for ResizeFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resource reservation resize incomplete")
    }
}

impl Error for ResizeFailure {}

pub(super) struct ResizeCommit {
    pub(super) owner: ChargeOwner,
    pub(super) outcome: ResizeOutcome,
}
