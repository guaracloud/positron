//! Fixed protected pools for closed recovery work kinds.

use super::{GovernorFailure, RecoveryWorkKind, ResourceAmounts, ResourceDimension};

/// Fixed protected capacities for every Release 1 recovery kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryPoolCapacities {
    durability: ResourceAmounts,
    retention: ResourceAmounts,
    compaction: ResourceAmounts,
    purge: ResourceAmounts,
    repair: ResourceAmounts,
    fencing: ResourceAmounts,
    shutdown: ResourceAmounts,
}

impl RecoveryPoolCapacities {
    pub(super) const fn from_raw(values: [ResourceAmounts; 7]) -> Self {
        let [
            durability,
            retention,
            compaction,
            purge,
            repair,
            fencing,
            shutdown,
        ] = values;
        Self {
            durability,
            retention,
            compaction,
            purge,
            repair,
            fencing,
            shutdown,
        }
    }

    pub fn new(
        durability: ResourceAmounts,
        retention: ResourceAmounts,
        compaction: ResourceAmounts,
        purge: ResourceAmounts,
        repair: ResourceAmounts,
        fencing: ResourceAmounts,
        shutdown: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        let candidate = Self {
            durability,
            retention,
            compaction,
            purge,
            repair,
            fencing,
            shutdown,
        };
        if RecoveryWorkKind::ALL
            .iter()
            .any(|kind| !candidate.get(*kind).all_positive())
        {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        candidate
            .protected_sum()
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        Ok(candidate)
    }

    #[must_use]
    pub const fn get(self, kind: RecoveryWorkKind) -> ResourceAmounts {
        match kind {
            RecoveryWorkKind::DurabilityCompletion => self.durability,
            RecoveryWorkKind::Retention => self.retention,
            RecoveryWorkKind::EmergencyCompaction => self.compaction,
            RecoveryWorkKind::Purge => self.purge,
            RecoveryWorkKind::Repair => self.repair,
            RecoveryWorkKind::Fencing => self.fencing,
            RecoveryWorkKind::SafeShutdown => self.shutdown,
        }
    }

    pub(super) fn protected_sum(self) -> Option<ResourceAmounts> {
        let mut total = ResourceAmounts::zero();
        for kind in RecoveryWorkKind::ALL {
            total = total.checked_add(self.get(kind))?;
        }
        Some(total)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecoveryPoolUsage {
    shared: ResourceAmounts,
    protected: [ResourceAmounts; 7],
}

impl RecoveryPoolUsage {
    pub(super) const fn zero() -> Self {
        Self {
            shared: ResourceAmounts::zero(),
            protected: [ResourceAmounts::zero(); 7],
        }
    }

    pub(super) const fn shared(self) -> ResourceAmounts {
        self.shared
    }

    pub(super) fn protected(self, kind: RecoveryWorkKind) -> ResourceAmounts {
        self.protected
            .get(kind.index())
            .copied()
            .unwrap_or(ResourceAmounts::zero())
    }

    pub(super) fn checked_add(self, charge: RecoveryPoolCharge) -> Option<Self> {
        let mut next = self;
        next.shared = next.shared.checked_add(charge.shared)?;
        let slot = next.protected.get_mut(charge.kind.index())?;
        *slot = slot.checked_add(charge.protected)?;
        Some(next)
    }

    pub(super) fn checked_sub(self, charge: RecoveryPoolCharge) -> Option<Self> {
        let mut next = self;
        next.shared = next.shared.checked_sub(charge.shared)?;
        let slot = next.protected.get_mut(charge.kind.index())?;
        *slot = slot.checked_sub(charge.protected)?;
        Some(next)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecoveryPoolCharge {
    pub(super) kind: RecoveryWorkKind,
    pub(super) shared: ResourceAmounts,
    pub(super) protected: ResourceAmounts,
}

pub(super) enum RecoveryPoolLimit {
    Global(ResourceDimension),
    Scope(ResourceDimension),
    Internal,
}

#[derive(Clone, Copy)]
pub(super) struct RecoveryPoolView {
    pub(super) shared_capacity: ResourceAmounts,
    pub(super) protected_capacity: ResourceAmounts,
    pub(super) usage: RecoveryPoolUsage,
    pub(super) shared_occupied_by_ordinary: ResourceAmounts,
}

pub(super) fn plan_recovery_charge(
    kind: RecoveryWorkKind,
    requested: ResourceAmounts,
    global: RecoveryPoolView,
    scope: RecoveryPoolView,
) -> Result<RecoveryPoolCharge, RecoveryPoolLimit> {
    let mut shared = ResourceAmounts::zero();
    let mut protected = ResourceAmounts::zero();
    for dimension in ResourceDimension::ALL {
        let shared_available = global
            .shared_capacity
            .get(dimension)
            .checked_sub(global.usage.shared().get(dimension))
            .and_then(|available| {
                available.checked_sub(global.shared_occupied_by_ordinary.get(dimension))
            })
            .ok_or(RecoveryPoolLimit::Internal)?;
        let scope_shared_available = scope
            .shared_capacity
            .get(dimension)
            .checked_sub(scope.usage.shared().get(dimension))
            .and_then(|available| {
                available.checked_sub(scope.shared_occupied_by_ordinary.get(dimension))
            })
            .ok_or(RecoveryPoolLimit::Internal)?;
        let protected_available = global
            .protected_capacity
            .get(dimension)
            .checked_sub(global.usage.protected(kind).get(dimension))
            .ok_or(RecoveryPoolLimit::Internal)?;
        let scope_protected_available = scope
            .protected_capacity
            .get(dimension)
            .checked_sub(scope.usage.protected(kind).get(dimension))
            .ok_or(RecoveryPoolLimit::Internal)?;
        let global_available = shared_available
            .checked_add(protected_available)
            .ok_or(RecoveryPoolLimit::Internal)?;
        let scope_available = scope_shared_available
            .checked_add(scope_protected_available)
            .ok_or(RecoveryPoolLimit::Internal)?;
        if requested.get(dimension) > global_available {
            return Err(RecoveryPoolLimit::Global(dimension));
        }
        if requested.get(dimension) > scope_available {
            return Err(RecoveryPoolLimit::Scope(dimension));
        }
        let requested_amount = requested.get(dimension);
        let global_required_shared = if requested_amount > protected_available {
            requested_amount
                .checked_sub(protected_available)
                .ok_or(RecoveryPoolLimit::Internal)?
        } else {
            0
        };
        let scope_required_shared = if requested_amount > scope_protected_available {
            requested_amount
                .checked_sub(scope_protected_available)
                .ok_or(RecoveryPoolLimit::Internal)?
        } else {
            0
        };
        let lower_shared = global_required_shared.max(scope_required_shared);
        let upper_shared = requested_amount
            .min(shared_available)
            .min(scope_shared_available);
        if lower_shared > upper_shared {
            return if global_required_shared > upper_shared {
                Err(RecoveryPoolLimit::Global(dimension))
            } else {
                Err(RecoveryPoolLimit::Scope(dimension))
            };
        }
        let shared_charge = upper_shared;
        let remainder = requested_amount
            .checked_sub(shared_charge)
            .ok_or(RecoveryPoolLimit::Internal)?;
        shared = shared.with_amount(dimension, shared_charge);
        protected = protected.with_amount(dimension, remainder);
    }
    Ok(RecoveryPoolCharge {
        kind,
        shared,
        protected,
    })
}

#[cfg(test)]
#[path = "tests/recovery_policy.rs"]
mod tests;
