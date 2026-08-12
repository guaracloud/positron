//! Preallocated, wait-free reservation-drop ledger.

#[cfg(test)]
use std::mem::size_of;
use std::sync::atomic::Ordering;

mod allocation;

pub(super) use allocation::{LedgerAllocation, allocate};

use super::accounting::{AccountingState, ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{RecoveryWorkKind, ReservationIdentity, WorkKind};
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
    kind: GrantKind,
}

impl GrantRecord {
    pub(super) fn new(
        owner: ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
    ) -> Option<Self> {
        let (tenant_index, kind, shared) = match (owner.attribution, identity) {
            (
                ChargeAttribution::Ordinary { tenant_index },
                ReservationIdentity::Ordinary { kind, .. },
            ) => (
                u16::try_from(tenant_index).ok()?,
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
                GrantKind::from_recovery(kind),
                owner.recovery_pools?.shared,
            ),
            _ => return None,
        };
        Some(Self {
            amounts,
            shared,
            tenant_index,
            kind,
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
        let replacement = Self::new(owner, identity, amounts)?;
        (replacement.kind == self.kind && replacement.tenant_index == self.tenant_index)
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
        let must_scan = self.has_pending_releases.swap(false, Ordering::AcqRel)
            || self.pending_fence.load(Ordering::Acquire);
        if !must_scan {
            return;
        }
        for (word_index, word) in self.pending_words.iter().enumerate() {
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
                let Some(signal) = self.slot_signals.get(index) else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                let Some(record_slot) = state.grant_records.get_mut(index) else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                if signal.load(Ordering::Acquire) != SLOT_RELEASE_PENDING {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                }
                let Some(record) = record_slot.take() else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                let released = self.release_record_locked(state, record);
                if !released.applied || state.free_slots.len() == state.grant_records.len() {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                }
                signal.store(SLOT_FREE, Ordering::Release);
                let Ok(slot) = u16::try_from(index) else {
                    state.lifecycle = super::GovernorLifecycle::Fenced;
                    continue;
                };
                state.free_slots.push(slot);
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
        let signal = self.slot_signals.get(index)?;
        if record_slot.is_some() || signal.load(Ordering::Acquire) != SLOT_FREE {
            return None;
        }
        *record_slot = Some(record);
        signal.store(SLOT_ACTIVE, Ordering::Release);
        Some(slot)
    }

    pub(super) fn mark_drop_pending(&self, slot: u16) {
        let index = usize::from(slot);
        let Some(signal) = self.slot_signals.get(index) else {
            self.pending_fence.store(true, Ordering::Release);
            return;
        };
        if signal
            .compare_exchange(
                SLOT_ACTIVE,
                SLOT_RELEASE_PENDING,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            self.pending_fence.store(true, Ordering::Release);
            return;
        }
        let word_index = index / 64;
        let bit = 1_u64 << (index % 64);
        let Some(word) = self.pending_words.get(word_index) else {
            self.pending_fence.store(true, Ordering::Release);
            return;
        };
        word.fetch_or(bit, Ordering::Release);
        self.has_pending_releases.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn mark_status_pending_for_test(&self, slot: u16) -> bool {
        self.slot_signals
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
        self.pending_words.get(index / 64).is_some_and(|word| {
            word.fetch_or(1_u64 << (index % 64), Ordering::Release);
            true
        })
    }

    #[cfg(test)]
    pub(super) fn publish_pending_hint_for_test(&self) {
        self.has_pending_releases.store(true, Ordering::Release);
    }

    pub(super) fn slot_is_active(&self, slot: u16) -> bool {
        self.slot_signals
            .get(usize::from(slot))
            .is_some_and(|signal| signal.load(Ordering::Acquire) == SLOT_ACTIVE)
    }

    pub(super) fn finish_slot(&self, state: &mut AccountingState, slot: u16) -> bool {
        let index = usize::from(slot);
        let Some(record) = state.grant_records.get_mut(index) else {
            return false;
        };
        let Some(signal) = self.slot_signals.get(index) else {
            return false;
        };
        if signal.load(Ordering::Acquire) != SLOT_ACTIVE || record.take().is_none() {
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
