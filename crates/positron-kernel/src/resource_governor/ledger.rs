//! Preallocated, wait-free reservation-drop ledger.

#[cfg(test)]
use std::mem::size_of;
use std::sync::atomic::Ordering;

use positron_domain::identity::{PrincipalId, TenantId};

mod allocation;
mod drop_ledger;

pub(super) use allocation::{LedgerAllocation, allocate};
pub(super) use drop_ledger::DropLedger;

use super::accounting::{AccountingState, ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{OperationToken, RecoveryWorkKind, ReservationIdentity, WorkKind};
use super::model::ResourceAmounts;
use super::policy::{OrdinaryPool, PoolCharge};
use super::recovery_policy::RecoveryPoolCharge;

const SLOT_FREE: u8 = 0;
const SLOT_ACTIVE: u8 = 1;
const SLOT_RELEASE_PENDING: u8 = 2;
const SYSTEM_TENANT_INDEX: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum GrantKind {
    SecurityLifecycle,
    Ingest,
    InteractiveQueryTail,
    OrdinaryMaintenanceBackup,
    DurabilityCompletion,
    Retention,
    EmergencyCompaction,
    Purge,
    Repair,
    Fencing,
    SafeShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct GrantRecord {
    amounts: ResourceAmounts,
    shared: ResourceAmounts,
    tenant_index: u16,
    tenant: Option<TenantId>,
    principal: Option<PrincipalId>,
    kind: GrantKind,
    operation: Option<OperationRecord>,
}

/// Fixed-size operation metadata retained in the same preallocated grant
/// ledger. A released root stays occupied until its children are gone, which
/// prevents a stale child token from attaching to a reused slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OperationRecord {
    Root {
        generation: u64,
        accepting_children: bool,
        child_count: u16,
    },
    Child {
        root_slot: u16,
        generation: u64,
    },
}

impl GrantRecord {
    pub(super) fn new(
        owner: ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
        operation: Option<OperationRecord>,
    ) -> Option<Self> {
        let (tenant_index, tenant, principal, kind, shared) = match (owner.attribution, identity) {
            (
                ChargeAttribution::Ordinary { tenant_index },
                ReservationIdentity::Ordinary {
                    tenant,
                    principal,
                    kind,
                },
            ) => (
                u16::try_from(tenant_index).ok()?,
                Some(tenant),
                principal,
                GrantKind::from_ordinary(kind),
                owner.pools?.shared(),
            ),
            (
                ChargeAttribution::Recovery { tenant_index },
                ReservationIdentity::Recovery { kind, .. },
            ) => (
                tenant_index
                    .map(u16::try_from)
                    .transpose()
                    .ok()?
                    .unwrap_or(SYSTEM_TENANT_INDEX),
                None,
                None,
                GrantKind::from_recovery(kind),
                owner.recovery_pools?.shared,
            ),
            _ => return None,
        };
        Some(Self {
            amounts,
            shared,
            tenant_index,
            tenant,
            principal,
            kind,
            operation,
        })
    }

    pub(super) const fn amounts(self) -> ResourceAmounts {
        self.amounts
    }

    pub(super) const fn tenant_index(self) -> Option<usize> {
        if self.tenant_index == SYSTEM_TENANT_INDEX {
            None
        } else {
            Some(self.tenant_index as usize)
        }
    }

    pub(super) const fn principal(self) -> Option<PrincipalId> {
        self.principal
    }

    pub(super) const fn tenant(self) -> Option<TenantId> {
        self.tenant
    }

    pub(super) const fn operation(self) -> Option<OperationRecord> {
        self.operation
    }

    pub(super) const fn is_operation_root(self) -> bool {
        matches!(self.operation, Some(OperationRecord::Root { .. }))
    }

    pub(super) fn root_token(self, governor: &GovernorInner, slot: u16) -> Option<OperationToken> {
        match self.operation {
            Some(OperationRecord::Root { generation, .. }) => Some(OperationToken {
                authority: std::sync::Arc::downgrade(&governor.drop_ledger),
                root_slot: slot,
                generation,
                tenant: self.tenant?,
                principal: self.principal?,
                kind: self.kind.ordinary_kind()?,
            }),
            Some(OperationRecord::Child { .. }) | None => None,
        }
    }

    pub(super) fn released_root(self) -> Option<Self> {
        match self.operation {
            Some(OperationRecord::Root {
                generation,
                child_count,
                ..
            }) => Some(Self {
                amounts: ResourceAmounts::zero(),
                shared: ResourceAmounts::zero(),
                tenant_index: self.tenant_index,
                tenant: self.tenant,
                principal: self.principal,
                kind: self.kind,
                operation: Some(OperationRecord::Root {
                    generation,
                    accepting_children: false,
                    child_count,
                }),
            }),
            Some(OperationRecord::Child { .. }) | None => None,
        }
    }

    pub(super) fn increment_root_child(self) -> Option<Self> {
        match self.operation {
            Some(OperationRecord::Root {
                generation,
                accepting_children: true,
                child_count,
            }) => Some(Self {
                operation: Some(OperationRecord::Root {
                    generation,
                    accepting_children: true,
                    child_count: child_count.checked_add(1)?,
                }),
                ..self
            }),
            _ => None,
        }
    }

    pub(super) fn decrement_root_child(self) -> Option<(Self, bool)> {
        match self.operation {
            Some(OperationRecord::Root {
                generation,
                accepting_children,
                child_count,
            }) => {
                let remaining = child_count.checked_sub(1)?;
                let remove = !accepting_children && remaining == 0;
                Some((
                    Self {
                        operation: Some(OperationRecord::Root {
                            generation,
                            accepting_children,
                            child_count: remaining,
                        }),
                        ..self
                    },
                    remove,
                ))
            },
            _ => None,
        }
    }

    pub(super) const fn is_ordinary(self) -> bool {
        self.kind.ordinary_kind().is_some()
    }

    pub(super) const fn class(self) -> super::WorkClass {
        match self.kind.ordinary_kind() {
            Some(kind) => kind.class(),
            None => super::WorkClass::DurabilityRecovery,
        }
    }

    pub(super) const fn recovery_kind(self) -> Option<RecoveryWorkKind> {
        self.kind.recovery_kind()
    }

    pub(super) fn owner(self) -> Option<ChargeOwner> {
        let protected = self.amounts.checked_sub(self.shared)?;
        if let Some(kind) = self.kind.ordinary_kind() {
            let class_pool = OrdinaryPool::for_class(kind.class())?;
            Some(ChargeOwner {
                attribution: ChargeAttribution::Ordinary {
                    tenant_index: self.tenant_index()?,
                },
                pools: Some(PoolCharge::new(class_pool, self.shared, protected)),
                recovery_pools: None,
            })
        } else {
            let kind = self.kind.recovery_kind()?;
            Some(ChargeOwner {
                attribution: ChargeAttribution::Recovery {
                    tenant_index: self.tenant_index(),
                },
                pools: None,
                recovery_pools: Some(RecoveryPoolCharge {
                    kind,
                    shared: self.shared,
                    protected,
                }),
            })
        }
    }

    pub(super) fn replaced(
        self,
        owner: ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
    ) -> Option<Self> {
        let replacement = Self::new(owner, identity, amounts, self.operation)?;
        (replacement.kind == self.kind
            && replacement.tenant_index == self.tenant_index
            && replacement.tenant == self.tenant
            && replacement.principal == self.principal)
            .then_some(replacement)
    }
}

impl GrantKind {
    const fn from_ordinary(kind: WorkKind) -> Self {
        match kind {
            WorkKind::SecurityLifecycle => Self::SecurityLifecycle,
            WorkKind::Ingest => Self::Ingest,
            WorkKind::InteractiveQueryTail => Self::InteractiveQueryTail,
            WorkKind::OrdinaryMaintenanceBackup => Self::OrdinaryMaintenanceBackup,
        }
    }

    const fn from_recovery(kind: RecoveryWorkKind) -> Self {
        match kind {
            RecoveryWorkKind::DurabilityCompletion => Self::DurabilityCompletion,
            RecoveryWorkKind::Retention => Self::Retention,
            RecoveryWorkKind::EmergencyCompaction => Self::EmergencyCompaction,
            RecoveryWorkKind::Purge => Self::Purge,
            RecoveryWorkKind::Repair => Self::Repair,
            RecoveryWorkKind::Fencing => Self::Fencing,
            RecoveryWorkKind::SafeShutdown => Self::SafeShutdown,
        }
    }

    const fn ordinary_kind(self) -> Option<WorkKind> {
        match self {
            Self::SecurityLifecycle => Some(WorkKind::SecurityLifecycle),
            Self::Ingest => Some(WorkKind::Ingest),
            Self::InteractiveQueryTail => Some(WorkKind::InteractiveQueryTail),
            Self::OrdinaryMaintenanceBackup => Some(WorkKind::OrdinaryMaintenanceBackup),
            _ => None,
        }
    }

    const fn recovery_kind(self) -> Option<RecoveryWorkKind> {
        match self {
            Self::DurabilityCompletion => Some(RecoveryWorkKind::DurabilityCompletion),
            Self::Retention => Some(RecoveryWorkKind::Retention),
            Self::EmergencyCompaction => Some(RecoveryWorkKind::EmergencyCompaction),
            Self::Purge => Some(RecoveryWorkKind::Purge),
            Self::Repair => Some(RecoveryWorkKind::Repair),
            Self::Fencing => Some(RecoveryWorkKind::Fencing),
            Self::SafeShutdown => Some(RecoveryWorkKind::SafeShutdown),
            _ => None,
        }
    }
}

impl GovernorInner {
    pub(super) fn drain_pending(&self, state: &mut AccountingState) {
        let must_scan = self
            .drop_ledger
            .has_pending_releases
            .swap(false, Ordering::AcqRel)
            || self.drop_ledger.pending_fence.load(Ordering::Acquire);
        if !must_scan {
            return;
        }
        for (word_index, word) in self.drop_ledger.pending_words.iter().enumerate() {
            let mut bits = word.swap(0, Ordering::AcqRel);
            while bits != 0 {
                let bit_index = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let Some(index) = word_index
                    .checked_mul(64)
                    .and_then(|base| base.checked_add(bit_index))
                else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                let Some(signal) = self.drop_ledger.slot_signals.get(index) else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                if signal.load(Ordering::Acquire) != SLOT_RELEASE_PENDING {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                }
                let Ok(slot) = u16::try_from(index) else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                let released = self.release_slot_locked(state, false, slot);
                if !released.applied {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                }
            }
        }
    }

    pub(super) fn activate_slot(
        &self,
        state: &mut AccountingState,
        record: GrantRecord,
    ) -> Option<u16> {
        let slot = state.free_slots.pop()?;
        let index = usize::from(slot);
        let record_slot = state.grant_records.get_mut(index)?;
        let signal = self.drop_ledger.slot_signals.get(index)?;
        if record_slot.is_some() || signal.load(Ordering::Acquire) != SLOT_FREE {
            return None;
        }
        *record_slot = Some(record);
        signal.store(SLOT_ACTIVE, Ordering::Release);
        Some(slot)
    }

    pub(super) fn mark_drop_pending(&self, slot: u16) {
        self.drop_ledger.mark_drop_pending(slot);
    }

    pub(super) fn mark_foreign_release(&self) {
        self.drop_ledger.mark_foreign_release();
    }

    #[cfg(test)]
    pub(super) fn mark_status_pending_for_test(&self, slot: u16) -> bool {
        self.drop_ledger
            .slot_signals
            .get(usize::from(slot))
            .is_some_and(|signal| {
                signal
                    .compare_exchange(
                        SLOT_ACTIVE,
                        SLOT_RELEASE_PENDING,
                        Ordering::Release,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            })
    }

    #[cfg(test)]
    pub(super) fn publish_pending_bit_for_test(&self, slot: u16) -> bool {
        let index = usize::from(slot);
        self.drop_ledger
            .pending_words
            .get(index / 64)
            .is_some_and(|word| {
                word.fetch_or(1_u64 << (index % 64), Ordering::Release);
                true
            })
    }

    #[cfg(test)]
    pub(super) fn publish_pending_hint_for_test(&self) {
        self.drop_ledger
            .has_pending_releases
            .store(true, Ordering::Release);
    }

    pub(super) fn slot_is_active(&self, slot: u16) -> bool {
        self.drop_ledger
            .slot_signals
            .get(usize::from(slot))
            .is_some_and(|signal| signal.load(Ordering::Acquire) == SLOT_ACTIVE)
    }

    pub(super) fn finish_slot(&self, state: &mut AccountingState, slot: u16) -> bool {
        let index = usize::from(slot);
        let Some(record) = state.grant_records.get_mut(index) else {
            return false;
        };
        let Some(signal) = self.drop_ledger.slot_signals.get(index) else {
            return false;
        };
        let signal_state = signal.load(Ordering::Acquire);
        if !matches!(signal_state, SLOT_ACTIVE | SLOT_RELEASE_PENDING) || record.take().is_none() {
            return false;
        }
        if state.free_slots.len() == state.grant_records.len() {
            return false;
        }
        signal.store(SLOT_FREE, Ordering::Release);
        state.free_slots.push(slot);
        true
    }

    pub(super) fn replace_slot_record(
        &self,
        state: &mut AccountingState,
        slot: u16,
        owner: ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
    ) -> bool {
        if !self.slot_is_active(slot) {
            return false;
        }
        let Some(record) = state.grant_records.get_mut(usize::from(slot)) else {
            return false;
        };
        let Some(current) = *record else {
            return false;
        };
        let Some(replacement) = current.replaced(owner, identity, amounts) else {
            return false;
        };
        *record = Some(replacement);
        true
    }
}

#[cfg(test)]
pub(super) const fn record_size_for_test() -> usize {
    size_of::<Option<GrantRecord>>()
}

#[cfg(test)]
#[path = "tests/ledger.rs"]
mod tests;
