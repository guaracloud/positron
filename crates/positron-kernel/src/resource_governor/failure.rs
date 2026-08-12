//! Stable, bounded governor failure evidence.

use std::error::Error;
use std::fmt::{Display, Formatter};

use super::claim::WorkClass;
use super::model::ResourceDimension;
use positron_domain::identity::TenantId;

/// Typed governor establishment or state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernorFailure {
    InvalidConfiguration,
    PolicyCardinalityExceeded,
    GovernorBootstrapInventoryUnavailable {
        required: super::ResourceAmounts,
    },
    InsufficientOutstandingProgress {
        configured: u32,
        required: u32,
    },
    TenantProgressUnavailable {
        tenant: TenantId,
        class: WorkClass,
        dimension: ResourceDimension,
    },
    SystemRecoveryProgressUnavailable {
        kind: super::RecoveryWorkKind,
        dimension: ResourceDimension,
    },
    InvalidRecoveryScope,
    GovernorContended {
        pressure: DiskPressureState,
    },
    PrimaryVolumeObservationUnavailable,
    ObservedVolumeMismatch,
    InternalFenced,
}

impl Display for GovernorFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "resource governor configuration is invalid",
            Self::PolicyCardinalityExceeded => "resource governor policy cardinality exceeded",
            Self::GovernorBootstrapInventoryUnavailable { .. } => {
                "resource governor bootstrap inventory is unavailable"
            },
            Self::InsufficientOutstandingProgress { .. } => {
                "resource governor outstanding progress is unavailable"
            },
            Self::TenantProgressUnavailable { .. } => {
                "resource governor tenant progress is unavailable"
            },
            Self::SystemRecoveryProgressUnavailable { .. } => {
                "resource governor system recovery progress is unavailable"
            },
            Self::InvalidRecoveryScope => "recovery work kind is invalid for the requested scope",
            Self::GovernorContended { .. } => "resource governor is contended",
            Self::PrimaryVolumeObservationUnavailable => {
                "primary data volume observation is unavailable"
            },
            Self::ObservedVolumeMismatch => {
                "resource observation does not match the primary data volume"
            },
            Self::InternalFenced => "resource governor internal state is fenced",
        })
    }
}

impl Error for GovernorFailure {}

/// Stable admission outcome classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionFailureCode {
    CapacityExhausted,
    TenantQuotaExceeded,
    UnregisteredTenant,
    OutstandingReservationLimit,
    ProtectedCapacityUnavailable,
    ClassCapacityUnavailable,
    TenantFairShareExceeded,
    CapacityOccupiedByRecovery,
    DiskPressureAdmissionRefused,
    RecoveryReserveExhausted,
    ShuttingDown,
    InternalFenced,
    GovernorContended,
}

impl AdmissionFailureCode {
    pub(super) const COUNT: usize = 13;

    pub(super) const fn index(self) -> usize {
        match self {
            Self::CapacityExhausted => 0,
            Self::TenantQuotaExceeded => 1,
            Self::UnregisteredTenant => 2,
            Self::OutstandingReservationLimit => 3,
            Self::ProtectedCapacityUnavailable => 4,
            Self::ClassCapacityUnavailable => 5,
            Self::TenantFairShareExceeded => 6,
            Self::CapacityOccupiedByRecovery => 7,
            Self::DiskPressureAdmissionRefused => 8,
            Self::RecoveryReserveExhausted => 9,
            Self::ShuttingDown => 10,
            Self::InternalFenced => 11,
            Self::GovernorContended => 12,
        }
    }

    pub(super) const fn from_index(index: usize) -> Option<Self> {
        Some(match index {
            0 => Self::CapacityExhausted,
            1 => Self::TenantQuotaExceeded,
            2 => Self::UnregisteredTenant,
            3 => Self::OutstandingReservationLimit,
            4 => Self::ProtectedCapacityUnavailable,
            5 => Self::ClassCapacityUnavailable,
            6 => Self::TenantFairShareExceeded,
            7 => Self::CapacityOccupiedByRecovery,
            8 => Self::DiskPressureAdmissionRefused,
            9 => Self::RecoveryReserveExhausted,
            10 => Self::ShuttingDown,
            11 => Self::InternalFenced,
            12 => Self::GovernorContended,
            _ => return None,
        })
    }

    pub(super) const fn is_throttle(self) -> bool {
        !matches!(
            self,
            Self::UnregisteredTenant | Self::ShuttingDown | Self::InternalFenced
        )
    }
}

/// Stable retry guidance for an admission refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRetry {
    AfterCapacityRelease,
    AfterPressureTransition,
    AfterExternalCorrection,
    Never,
}

/// The authoritative scope that limited admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitingScope {
    Global,
    Tenant,
    RecoveryReserve,
    ProtectedReserve,
    OutstandingReservations,
    ClassHeadroom,
    TenantFairShare,
    RecoveryOccupancy,
    Policy,
    Internal,
}

/// The derived disk admission state at the decision point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskPressureState {
    Healthy,
    SoftPressure,
    HardPressure,
}

/// Whether a refusal changed reservation ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionCompletionState {
    RejectedBeforeReservation,
    ExistingReservationRetained,
}

/// A typed, fixed-cardinality admission refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionFailure {
    code: AdmissionFailureCode,
    retry: AdmissionRetry,
    scope: LimitingScope,
    class: WorkClass,
    pressure: DiskPressureState,
    completion: AdmissionCompletionState,
    dimension: Option<ResourceDimension>,
    allowed: u64,
    in_use: u64,
    requested: u64,
}

pub(super) struct AdmissionEvidence {
    pub(super) code: AdmissionFailureCode,
    pub(super) retry: AdmissionRetry,
    pub(super) scope: LimitingScope,
    pub(super) class: WorkClass,
    pub(super) pressure: DiskPressureState,
    pub(super) dimension: Option<ResourceDimension>,
    pub(super) allowed: u64,
    pub(super) in_use: u64,
    pub(super) requested: u64,
}

impl AdmissionFailure {
    pub(super) const fn new(evidence: AdmissionEvidence) -> Self {
        Self {
            code: evidence.code,
            retry: evidence.retry,
            scope: evidence.scope,
            class: evidence.class,
            pressure: evidence.pressure,
            completion: AdmissionCompletionState::RejectedBeforeReservation,
            dimension: evidence.dimension,
            allowed: evidence.allowed,
            in_use: evidence.in_use,
            requested: evidence.requested,
        }
    }

    pub(super) const fn at_pressure(mut self, pressure: DiskPressureState) -> Self {
        self.pressure = pressure;
        self
    }

    #[must_use]
    pub const fn code(&self) -> AdmissionFailureCode {
        self.code
    }

    #[must_use]
    pub const fn retry(&self) -> AdmissionRetry {
        self.retry
    }

    #[must_use]
    pub const fn limiting_scope(&self) -> LimitingScope {
        self.scope
    }

    #[must_use]
    pub const fn work_class(&self) -> WorkClass {
        self.class
    }

    #[must_use]
    pub const fn pressure_state(&self) -> DiskPressureState {
        self.pressure
    }

    #[must_use]
    pub const fn completion_state(&self) -> AdmissionCompletionState {
        self.completion
    }

    #[must_use]
    pub const fn limiting_dimension(&self) -> Option<ResourceDimension> {
        self.dimension
    }

    #[must_use]
    pub const fn allowed(&self) -> u64 {
        self.allowed
    }

    #[must_use]
    pub const fn in_use(&self) -> u64 {
        self.in_use
    }

    #[must_use]
    pub const fn requested(&self) -> u64 {
        self.requested
    }
}

impl Display for AdmissionFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resource admission refused")
    }
}

impl Error for AdmissionFailure {}
