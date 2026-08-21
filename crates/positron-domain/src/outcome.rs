//! Closed typed failures returned by Domain Types.

use std::error::Error;
use std::fmt::{Display, Formatter};

/// The stable class of a rejected foundational domain operation.
///
/// This closed code is intended for caller control flow; human-readable error
/// text is not a compatibility surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainFailureCode {
    /// An identity violates the canonical native representation.
    InvalidIdentifier,
    /// An attribution would grant a system identity a tenant data-plane role.
    InvalidAttribution,
    /// A tenant lifecycle handoff is not legal from its current state.
    InvalidLifecycleTransition,
    /// A present source time conflicts with its quality annotation.
    InvalidTimeAnnotation,
    /// A checked monotonically ordered value would wrap.
    ArithmeticOverflow,
    /// A tenant value-limit profile attempts to exceed a system ceiling.
    LimitExceedsSystem,
    /// A numeric value limit is zero and cannot bound work or allocation.
    InvalidLimit,
    /// An unvalidated attribute exceeds its effective value-limit profile.
    ValueLimitExceeded,
    /// Validation could not reserve bounded memory for the later native state.
    AllocationUnavailable,
}

/// The retry classification attached to a domain failure.
///
/// Identifier validation cannot succeed through a blind retry; the caller must
/// provide corrected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    /// Retrying the same request cannot change the rejected result.
    Never,
    /// A bounded resource may become available after owner-directed backoff.
    AfterBackoff,
    /// The caller must correct the supplied native value before retrying.
    AfterInputCorrection,
}

/// The completion truth attached to a domain failure.
///
/// Identifier rejection occurs before any owning durable operation starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionState {
    /// Input was rejected before the owning operation began.
    Rejected,
}

/// The safe semantic location that produced a domain failure.
///
/// This context contains no input value or tenant data and is safe for bounded
/// diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureSource {
    /// A tenant identity check failed.
    TenantId,
    /// A tenant slug check failed.
    TenantSlug,
    /// A principal identity check failed.
    PrincipalId,
    /// A tenant attribution check failed.
    TenantAttribution,
    /// A tenant lifecycle transition check failed.
    TenantLifecycle,
    /// A source-time annotation check failed.
    SourceTime,
    /// A virtual shard identity check failed.
    VirtualShard,
    /// An assignment epoch progression check failed.
    AssignmentEpoch,
    /// A commit-position progression check failed.
    CommitPosition,
    /// A committed Store Block record ordinal exceeded its bounded identity space.
    RecordOrdinal,
    /// A system-versus-tenant profile relationship check failed.
    ValueLimitProfile,
    /// A unit value-limit check failed.
    ValueLimit,
    /// Dynamic attribute validation failed.
    AttributeValue,
}

/// A typed rejection from the foundational Domain Types boundary.
///
/// It retains a stable code, retry classification, completion truth, and safe
/// semantic source, but intentionally retains no tenant input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainFailure {
    code: DomainFailureCode,
    retry_class: RetryClass,
    completion_state: CompletionState,
    source: FailureSource,
}

impl DomainFailure {
    /// Returns the stable code that callers use for typed control flow.
    #[must_use]
    pub const fn code(self) -> DomainFailureCode {
        self.code
    }

    /// Returns whether corrected native input is required before retrying.
    #[must_use]
    pub const fn retry_class(self) -> RetryClass {
        self.retry_class
    }

    /// Returns the truthful completion state for the rejected operation.
    #[must_use]
    pub const fn completion_state(self) -> CompletionState {
        self.completion_state
    }

    /// Returns the bounded semantic source of this failure.
    #[must_use]
    pub const fn source(self) -> FailureSource {
        self.source
    }

    pub(crate) const fn invalid_identifier(source: FailureSource) -> Self {
        Self {
            code: DomainFailureCode::InvalidIdentifier,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
        }
    }

    pub(crate) const fn invalid_attribution() -> Self {
        Self {
            code: DomainFailureCode::InvalidAttribution,
            retry_class: RetryClass::Never,
            completion_state: CompletionState::Rejected,
            source: FailureSource::TenantAttribution,
        }
    }

    pub(crate) const fn invalid_lifecycle_transition() -> Self {
        Self {
            code: DomainFailureCode::InvalidLifecycleTransition,
            retry_class: RetryClass::Never,
            completion_state: CompletionState::Rejected,
            source: FailureSource::TenantLifecycle,
        }
    }

    pub(crate) const fn invalid_time_annotation() -> Self {
        Self {
            code: DomainFailureCode::InvalidTimeAnnotation,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source: FailureSource::SourceTime,
        }
    }

    pub(crate) const fn arithmetic_overflow(source: FailureSource) -> Self {
        Self {
            code: DomainFailureCode::ArithmeticOverflow,
            retry_class: RetryClass::Never,
            completion_state: CompletionState::Rejected,
            source,
        }
    }

    pub(crate) const fn limit_exceeds_system() -> Self {
        Self {
            code: DomainFailureCode::LimitExceedsSystem,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source: FailureSource::ValueLimitProfile,
        }
    }

    pub(crate) const fn invalid_limit(source: FailureSource) -> Self {
        Self {
            code: DomainFailureCode::InvalidLimit,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source,
        }
    }

    pub(crate) const fn value_limit_exceeded() -> Self {
        Self {
            code: DomainFailureCode::ValueLimitExceeded,
            retry_class: RetryClass::AfterInputCorrection,
            completion_state: CompletionState::Rejected,
            source: FailureSource::AttributeValue,
        }
    }

    pub(crate) const fn allocation_unavailable() -> Self {
        Self {
            code: DomainFailureCode::AllocationUnavailable,
            retry_class: RetryClass::AfterBackoff,
            completion_state: CompletionState::Rejected,
            source: FailureSource::AttributeValue,
        }
    }
}

impl Display for DomainFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.code {
            DomainFailureCode::InvalidIdentifier => "invalid domain identifier",
            DomainFailureCode::InvalidAttribution => "invalid tenant attribution",
            DomainFailureCode::InvalidLifecycleTransition => "invalid tenant lifecycle transition",
            DomainFailureCode::InvalidTimeAnnotation => "invalid source-time annotation",
            DomainFailureCode::ArithmeticOverflow => "domain arithmetic overflow",
            DomainFailureCode::LimitExceedsSystem => "tenant limit exceeds system ceiling",
            DomainFailureCode::InvalidLimit => "invalid value limit",
            DomainFailureCode::ValueLimitExceeded => "dynamic value exceeds its effective limit",
            DomainFailureCode::AllocationUnavailable => "bounded validation allocation unavailable",
        })
    }
}

impl Error for DomainFailure {}
