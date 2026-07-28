//! Checked tenant lifecycle transitions.

use crate::outcome::DomainFailure;

/// The durable lifecycle state for one tenant.
///
/// The names form a closed native taxonomy, not a persistence encoding.
/// `TenantLifecycle` owns checked transitions so Purging cannot return to a
/// reversible state and Purged remains terminal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TenantLifecycleState {
    /// Ingest, query, tail, and tenant administration can be admitted by their owners.
    Active,
    /// New ingestion is rejected while bounded retained-data access remains possible.
    ReadOnly,
    /// Tenant data-plane traffic is closed while system recovery remains possible.
    Suspended,
    /// Irreversible tenant purge is in progress.
    Purging,
    /// The terminal state retaining only non-reusable identity and governance evidence.
    Purged,
}

/// A lifecycle value whose transitions enforce reversible and irreversible states.
///
/// This type owns no durable storage. Administration and the Catalog own
/// publication; this boundary makes invalid transitions explicit before they
/// reach those owners. It makes no wire or durable serialization promise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantLifecycle {
    state: TenantLifecycleState,
}

impl TenantLifecycle {
    /// Creates the only initial tenant lifecycle state.
    #[must_use]
    pub const fn active() -> Self {
        Self {
            state: TenantLifecycleState::Active,
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(self) -> TenantLifecycleState {
        self.state
    }

    /// Moves a reversible state to ReadOnly.
    pub fn to_read_only(self) -> Result<Self, DomainFailure> {
        self.transition(TenantLifecycleState::ReadOnly)
    }

    /// Moves a reversible state to Suspended.
    pub fn to_suspended(self) -> Result<Self, DomainFailure> {
        self.transition(TenantLifecycleState::Suspended)
    }

    /// Moves a reversible state to Active.
    pub fn to_active(self) -> Result<Self, DomainFailure> {
        self.transition(TenantLifecycleState::Active)
    }

    /// Crosses the one-way boundary into Purging.
    pub fn begin_purge(self) -> Result<Self, DomainFailure> {
        self.transition(TenantLifecycleState::Purging)
    }

    /// Completes a previously started irreversible purge.
    pub fn complete_purge(self) -> Result<Self, DomainFailure> {
        self.transition(TenantLifecycleState::Purged)
    }

    fn transition(self, target: TenantLifecycleState) -> Result<Self, DomainFailure> {
        if lifecycle_transition_is_valid(self.state, target) {
            return Ok(Self { state: target });
        }
        Err(DomainFailure::invalid_lifecycle_transition())
    }
}

const fn lifecycle_transition_is_valid(
    current: TenantLifecycleState,
    target: TenantLifecycleState,
) -> bool {
    matches!(
        (current, target),
        (TenantLifecycleState::Active, TenantLifecycleState::ReadOnly)
            | (
                TenantLifecycleState::Active,
                TenantLifecycleState::Suspended
            )
            | (TenantLifecycleState::Active, TenantLifecycleState::Purging)
            | (TenantLifecycleState::ReadOnly, TenantLifecycleState::Active)
            | (
                TenantLifecycleState::ReadOnly,
                TenantLifecycleState::Suspended
            )
            | (
                TenantLifecycleState::ReadOnly,
                TenantLifecycleState::Purging
            )
            | (
                TenantLifecycleState::Suspended,
                TenantLifecycleState::Active
            )
            | (
                TenantLifecycleState::Suspended,
                TenantLifecycleState::ReadOnly
            )
            | (
                TenantLifecycleState::Suspended,
                TenantLifecycleState::Purging
            )
            | (TenantLifecycleState::Purging, TenantLifecycleState::Purged)
    )
}
