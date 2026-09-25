//! Closed work identity and checked admission claims.

use positron_domain::identity::{PrincipalId, TenantId};

use super::failure::GovernorFailure;
use super::model::ResourceAmounts;

/// Product priority classes, highest priority first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClass {
    DurabilityRecovery,
    SecurityLifecycle,
    Ingest,
    InteractiveQueryTail,
    OrdinaryMaintenanceBackup,
}

/// Closed ordinary M1 work kinds. Recovery work is intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    SecurityLifecycle,
    Ingest,
    InteractiveQueryTail,
    OrdinaryMaintenanceBackup,
}

impl WorkKind {
    /// Returns the non-caller-selectable class used for admission policy.
    #[must_use]
    pub const fn class(self) -> WorkClass {
        match self {
            Self::SecurityLifecycle => WorkClass::SecurityLifecycle,
            Self::Ingest => WorkClass::Ingest,
            Self::InteractiveQueryTail => WorkClass::InteractiveQueryTail,
            Self::OrdinaryMaintenanceBackup => WorkClass::OrdinaryMaintenanceBackup,
        }
    }
}

/// A checked, multidimensional request to begin tenant work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkClaim {
    pub(super) tenant: TenantId,
    pub(super) principal: Option<PrincipalId>,
    pub(super) kind: WorkKind,
    pub(super) amounts: ResourceAmounts,
    pub(super) operation: Option<OperationToken>,
}

/// An opaque, in-memory capability for adding bounded sub-work to one live
/// authenticated operation. It is intentionally not serializable: resumed
/// cursors establish a fresh root operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationToken {
    pub(super) root_slot: u16,
    pub(super) generation: u64,
    pub(super) tenant: TenantId,
    pub(super) principal: PrincipalId,
    pub(super) kind: WorkKind,
}

impl WorkClaim {
    pub fn tenant(
        tenant: TenantId,
        kind: WorkKind,
        amounts: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if amounts.is_empty() {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            tenant,
            principal: None,
            kind,
            amounts,
            operation: None,
        })
    }

    /// Creates one post-authentication tenant operation attributed to its
    /// credential Principal. The Governor retains this identity in its fixed
    /// grant ledger so one Principal cannot consume unbounded concurrent work.
    pub fn authenticated(
        tenant: TenantId,
        principal: PrincipalId,
        kind: WorkKind,
        amounts: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if amounts.is_empty() {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            tenant,
            principal: Some(principal),
            kind,
            amounts,
            operation: None,
        })
    }

    /// Adds bounded work to a live authenticated operation. The Governor
    /// validates this opaque capability atomically at admission, including
    /// its root generation, tenant, Principal, and work class.
    pub fn authenticated_child(
        operation: OperationToken,
        kind: WorkKind,
        amounts: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if amounts.is_empty() || kind.class() != operation.kind.class() {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            tenant: operation.tenant,
            principal: Some(operation.principal),
            kind,
            amounts,
            operation: Some(operation),
        })
    }

    pub(super) const fn class(self) -> WorkClass {
        self.kind.class()
    }
}

/// Recovery Reserve consumers accepted by the Release 1 product contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryWorkKind {
    DurabilityCompletion,
    Retention,
    EmergencyCompaction,
    Purge,
    Repair,
    Fencing,
    SafeShutdown,
}

/// Cancellation semantics fixed by recovery work kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryInterruption {
    RetainUntilCompletion,
    CooperativeAtCheckpoint,
}

impl RecoveryWorkKind {
    pub(super) const ALL: [Self; 7] = [
        Self::DurabilityCompletion,
        Self::Retention,
        Self::EmergencyCompaction,
        Self::Purge,
        Self::Repair,
        Self::Fencing,
        Self::SafeShutdown,
    ];

    pub(super) const fn index(self) -> usize {
        match self {
            Self::DurabilityCompletion => 0,
            Self::Retention => 1,
            Self::EmergencyCompaction => 2,
            Self::Purge => 3,
            Self::Repair => 4,
            Self::Fencing => 5,
            Self::SafeShutdown => 6,
        }
    }
    /// Whether this kind may operate without tenant attribution.
    #[must_use]
    pub const fn permits_system_scope(self) -> bool {
        !matches!(self, Self::Retention | Self::Purge)
    }

    /// Whether this kind may operate against one tenant.
    #[must_use]
    pub const fn permits_tenant_scope(self) -> bool {
        !matches!(self, Self::Fencing | Self::SafeShutdown)
    }

    #[must_use]
    pub const fn interruption(self) -> RecoveryInterruption {
        match self {
            Self::DurabilityCompletion | Self::SafeShutdown => {
                RecoveryInterruption::RetainUntilCompletion
            },
            Self::Retention
            | Self::EmergencyCompaction
            | Self::Purge
            | Self::Repair
            | Self::Fencing => RecoveryInterruption::CooperativeAtCheckpoint,
        }
    }

    pub(super) const fn retains_capacity_on_resize_failure(self) -> bool {
        matches!(self, Self::DurabilityCompletion | Self::SafeShutdown)
    }
}

/// Bounded attribution for protected recovery work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryScope {
    System,
    Tenant(TenantId),
}

/// A checked claim against protected Recovery Reserve capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryWorkClaim {
    pub(super) scope: RecoveryScope,
    pub(super) kind: RecoveryWorkKind,
    pub(super) amounts: ResourceAmounts,
}

impl RecoveryWorkClaim {
    pub fn system(
        kind: RecoveryWorkKind,
        amounts: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if !kind.permits_system_scope() {
            return Err(GovernorFailure::InvalidRecoveryScope);
        }
        if amounts.is_empty() {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            scope: RecoveryScope::System,
            kind,
            amounts,
        })
    }

    pub fn tenant(
        tenant: TenantId,
        kind: RecoveryWorkKind,
        amounts: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if !kind.permits_tenant_scope() {
            return Err(GovernorFailure::InvalidRecoveryScope);
        }
        if amounts.is_empty() {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            scope: RecoveryScope::Tenant(tenant),
            kind,
            amounts,
        })
    }

    #[must_use]
    pub const fn scope(self) -> RecoveryScope {
        self.scope
    }
}

#[derive(Clone, Copy)]
pub(super) enum ReservationIdentity {
    Ordinary {
        tenant: TenantId,
        principal: Option<PrincipalId>,
        kind: WorkKind,
    },
    Recovery {
        scope: RecoveryScope,
        kind: RecoveryWorkKind,
    },
}

impl ReservationIdentity {
    pub(super) const fn class(self) -> WorkClass {
        match self {
            Self::Ordinary { kind, .. } => kind.class(),
            Self::Recovery { .. } => WorkClass::DurabilityRecovery,
        }
    }
}
