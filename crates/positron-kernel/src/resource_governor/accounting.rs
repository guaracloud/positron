//! Bounded governor state and synchronized snapshots.

mod setup;
mod snapshot;
#[cfg(test)]
mod test_support;

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use positron_domain::identity::TenantId;

use super::bootstrap::{BootstrapAllocationStage, BootstrapInventoryLayout};
use super::claim::WorkClass;
use super::decision::{
    DecisionLimit, contention_failure, failure, failure_at_pressure, internal_failure_at_pressure,
};
use super::failure::DiskPressureState;
use super::failure::{
    AdmissionFailure, AdmissionFailureCode, AdmissionRetry, GovernorFailure, LimitingScope,
};
use super::fairness::{
    amount_capacities, ordinary_capacities, recovery_pool_capacities as recovery_fair_capacities,
    system_recovery_capacities, total_weight, validate_progress, validate_system_recovery_progress,
};
use super::inventory::{DiskObservation, DiskPressureThresholds, TenantQuota};
use super::ledger::GrantRecord;
use super::lifecycle::{GovernorLifecycle, class_index, empty_class_counts};
use super::model::ResourceAmounts;
use super::policy::{PoolCapacities, PoolCharge};
use super::recovery_policy::{RecoveryPoolCapacities, RecoveryPoolCharge, RecoveryPoolUsage};

pub(super) struct GovernorInner {
    pub(super) ownership: KernelOwnership,
    pub(super) raw_effective: ResourceAmounts,
    pub(super) bootstrap_overhead: ResourceAmounts,
    pub(super) total_ceiling: ResourceAmounts,
    pub(super) ordinary_ceiling: ResourceAmounts,
    pub(super) recovery_reserve: ResourceAmounts,
    pub(super) tenant_quotas: Box<[TenantQuota]>,
    pub(super) maximum_outstanding: u32,
    pub(super) pool_capacities: PoolCapacities,
    pub(super) tenant_fair_capacities: Box<[PoolCapacities]>,
    pub(super) recovery_pool_capacities: RecoveryPoolCapacities,
    pub(super) recovery_shared_capacity: ResourceAmounts,
    pub(super) recovery_tenant_shared_fair: Box<[ResourceAmounts]>,
    pub(super) recovery_tenant_pool_fair: Box<[RecoveryPoolCapacities]>,
    pub(super) recovery_system_pool_capacities: RecoveryPoolCapacities,
    pub(super) disk_thresholds: DiskPressureThresholds,
    pub(super) state: Mutex<AccountingState>,
    pub(super) drop_ledger: Arc<super::ledger::DropLedger>,
    last_pressure: AtomicU8,
    contention_count: AtomicU64,
}

pub(super) enum KernelOwnership {
    Owned {
        volume: crate::OwnedPrimaryDataVolume,
    },
    #[cfg(any(test, fuzzing))]
    TestOnly,
}

pub(super) struct GovernorConfiguration {
    raw_effective: ResourceAmounts,
    bootstrap_overhead: ResourceAmounts,
    total_ceiling: ResourceAmounts,
    ordinary_ceiling: ResourceAmounts,
    recovery_reserve: ResourceAmounts,
    tenant_quotas: Box<[TenantQuota]>,
    maximum_outstanding: u32,
    pool_capacities: PoolCapacities,
    tenant_fair_capacities: Box<[PoolCapacities]>,
    recovery_pool_capacities: RecoveryPoolCapacities,
    recovery_shared_capacity: ResourceAmounts,
    recovery_tenant_shared_fair: Box<[ResourceAmounts]>,
    recovery_tenant_pool_fair: Box<[RecoveryPoolCapacities]>,
    recovery_system_pool_capacities: RecoveryPoolCapacities,
    disk_thresholds: DiskPressureThresholds,
    state: AccountingState,
    slot_signals: Box<[AtomicU8]>,
    pending_words: Box<[AtomicU64]>,
}

pub(super) struct GovernorSetupInput {
    pub(super) raw_effective: ResourceAmounts,
    pub(super) bootstrap_overhead: ResourceAmounts,
    pub(super) total_ceiling: ResourceAmounts,
    pub(super) ordinary_ceiling: ResourceAmounts,
    pub(super) tenant_quotas: Box<[TenantQuota]>,
    pub(super) maximum_outstanding: u32,
    pub(super) pool_capacities: PoolCapacities,
    pub(super) recovery_pool_capacities: RecoveryPoolCapacities,
    pub(super) disk_thresholds: DiskPressureThresholds,
    pub(super) initial_disk: DiskObservation,
    pub(super) layout: BootstrapInventoryLayout,
    pub(super) fail_at: Option<BootstrapAllocationStage>,
}

pub(super) struct AccountingState {
    pub(super) rejection_counts: [u64; AdmissionFailureCode::COUNT],
    pub(super) grant_records: Box<[Option<GrantRecord>]>,
    pub(super) free_slots: Vec<u16>,
    pub(super) total_usage: ResourceAmounts,
    pub(super) recovery_usage: ResourceAmounts,
    pub(super) ordinary_tenant_usage: Box<[ResourceAmounts]>,
    pub(super) recovery_tenant_usage: Box<[ResourceAmounts]>,
    pub(super) recovery_pool_usage: RecoveryPoolUsage,
    pub(super) recovery_system_pool_usage: RecoveryPoolUsage,
    pub(super) recovery_tenant_pool_usage: Box<[RecoveryPoolUsage]>,
    pub(super) pool_usage: PoolCapacities,
    pub(super) ordinary_tenant_pool_usage: Box<[PoolCapacities]>,
    pub(super) tenant_outstanding: Box<[u32]>,
    pub(super) outstanding: u32,
    pub(super) disk_pressure: DiskPressureState,
    pub(super) usable_disk_bytes: u64,
    pub(super) pressure_transition_count: u64,
    pub(super) lifecycle: GovernorLifecycle,
    pub(super) outstanding_ordinary: u32,
    pub(super) outstanding_recovery: u32,
    pub(super) outstanding_uninterruptible: u32,
    pub(super) class_counts: [u32; 5],
}

#[derive(Clone, Copy)]
pub(super) struct ChargeOwner {
    pub(super) attribution: ChargeAttribution,
    pub(super) pools: Option<PoolCharge>,
    pub(super) recovery_pools: Option<RecoveryPoolCharge>,
}

#[derive(Clone, Copy)]
pub(super) enum ChargeAttribution {
    Ordinary { tenant_index: usize },
    Recovery { tenant_index: Option<usize> },
}

#[derive(Clone, Copy)]
pub(super) struct AccountingSnapshot {
    pub(super) outstanding: u32,
    pub(super) maximum_outstanding: u32,
    pub(super) reserve_consumption: ResourceAmounts,
    pub(super) pool_capacities: PoolCapacities,
    pub(super) pool_usage: PoolCapacities,
    pub(super) disk_pressure: DiskPressureState,
    pub(super) pressure_transition_count: u64,
    pub(super) lifecycle: GovernorLifecycle,
    pub(super) total_usage: ResourceAmounts,
    pub(super) outstanding_ordinary: u32,
    pub(super) outstanding_recovery: u32,
    pub(super) outstanding_uninterruptible: u32,
    pub(super) class_counts: [u32; 5],
    pub(super) rejection_count: u64,
    pub(super) rejection_counts: [u64; AdmissionFailureCode::COUNT],
    pub(super) throttle_counts: [u64; AdmissionFailureCode::COUNT],
    pub(super) effective_capacity: ResourceAmounts,
    pub(super) bootstrap_overhead: ResourceAmounts,
    pub(super) ordinary_capacity: ResourceAmounts,
    pub(super) recovery_reserve: ResourceAmounts,
    pub(super) recovery_shared_capacity: ResourceAmounts,
    pub(super) recovery_shared_usage: ResourceAmounts,
    pub(super) recovery_pool_capacities: RecoveryPoolCapacities,
    pub(super) recovery_pool_usage: RecoveryPoolUsage,
    pub(super) usable_disk_bytes: u64,
}

impl GovernorInner {
    pub(super) fn tenant_index(
        &self,
        tenant: TenantId,
        class: WorkClass,
    ) -> Result<usize, AdmissionFailure> {
        self.tenant_quotas
            .iter()
            .position(|quota| quota.tenant == tenant)
            .ok_or_else(|| {
                failure(
                    AdmissionFailureCode::UnregisteredTenant,
                    AdmissionRetry::AfterExternalCorrection,
                    LimitingScope::Tenant,
                    class,
                    DecisionLimit::none(),
                )
            })
    }

    pub(super) fn lock_for_admission(
        &self,
        class: WorkClass,
    ) -> Result<MutexGuard<'_, AccountingState>, AdmissionFailure> {
        match self.state.try_lock() {
            Ok(mut state) => {
                self.drain_pending(&mut state);
                if self.drop_ledger.pending_fence.swap(false, Ordering::AcqRel) {
                    state.lifecycle = GovernorLifecycle::Fenced;
                }
                Ok(state)
            },
            Err(TryLockError::WouldBlock) => {
                if increment_checked(&self.contention_count).is_err() {
                    self.drop_ledger
                        .pending_fence
                        .store(true, Ordering::Release);
                }
                Err(contention_failure(class, self.last_pressure()))
            },
            Err(TryLockError::Poisoned(poisoned)) => {
                let mut state = poisoned.into_inner();
                state.lifecycle = GovernorLifecycle::Fenced;
                Err(internal_failure_at_pressure(class, state.disk_pressure))
            },
        }
    }

    pub(super) fn pressure_for_failure(&self) -> DiskPressureState {
        self.last_pressure()
    }

    pub(super) fn last_pressure(&self) -> DiskPressureState {
        pressure_from_index(self.last_pressure.load(Ordering::Acquire))
    }

    pub(super) fn publish_pressure(&self, pressure: DiskPressureState) {
        self.last_pressure
            .store(pressure_index(pressure), Ordering::Release);
    }

    pub(super) fn try_lock_for_control(
        &self,
    ) -> Result<MutexGuard<'_, AccountingState>, GovernorFailure> {
        match self.state.try_lock() {
            Ok(mut state) => {
                self.drain_pending(&mut state);
                if self.drop_ledger.pending_fence.swap(false, Ordering::AcqRel) {
                    state.lifecycle = GovernorLifecycle::Fenced;
                }
                Ok(state)
            },
            Err(TryLockError::WouldBlock) => Err(GovernorFailure::GovernorContended {
                pressure: self.last_pressure(),
            }),
            Err(TryLockError::Poisoned(poisoned)) => {
                poisoned.into_inner().lifecycle = GovernorLifecycle::Fenced;
                Err(GovernorFailure::InternalFenced)
            },
        }
    }

    pub(super) fn record_refusal_locked(
        &self,
        state: &mut AccountingState,
        failure: &AdmissionFailure,
    ) {
        if failure.code() == AdmissionFailureCode::GovernorContended {
            return;
        }
        let index = failure.code().index();
        let sum = state
            .rejection_counts
            .iter()
            .try_fold(0_u64, |total, count| total.checked_add(*count));
        let candidate = state
            .rejection_counts
            .get(index)
            .copied()
            .and_then(|count| count.checked_add(1));
        if sum.and_then(|total| total.checked_add(1)).is_none() || candidate.is_none() {
            state.lifecycle = GovernorLifecycle::Fenced;
            return;
        }
        if let (Some(slot), Some(candidate)) = (state.rejection_counts.get_mut(index), candidate) {
            *slot = candidate;
        } else {
            state.lifecycle = GovernorLifecycle::Fenced;
        }
    }

    pub(super) fn require_healthy_and_slot(
        &self,
        state: &AccountingState,
        class: WorkClass,
        tenant_index: Option<usize>,
    ) -> Result<u32, AdmissionFailure> {
        if state.lifecycle == GovernorLifecycle::Fenced {
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        }
        let candidate = state
            .outstanding
            .checked_add(1)
            .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
        let class_index = class_index(class);
        let missing_classes = state
            .class_counts
            .iter()
            .enumerate()
            .filter(|(index, count)| *index != class_index && **count == 0)
            .count();
        let missing_tenants = state
            .tenant_outstanding
            .iter()
            .enumerate()
            .filter(|(index, count)| Some(*index) != tenant_index && **count == 0)
            .count();
        let reserved_progress = u32::try_from(missing_classes)
            .ok()
            .and_then(|classes| {
                u32::try_from(missing_tenants)
                    .ok()
                    .and_then(|tenants| classes.checked_add(tenants))
            })
            .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
        let progress_bound = candidate.checked_add(reserved_progress);
        if progress_bound.is_none_or(|bound| bound > self.maximum_outstanding) {
            return Err(failure_at_pressure(
                AdmissionFailureCode::OutstandingReservationLimit,
                AdmissionRetry::AfterCapacityRelease,
                LimitingScope::OutstandingReservations,
                class,
                state.disk_pressure,
                DecisionLimit {
                    dimension: None,
                    allowed: u64::from(self.maximum_outstanding),
                    in_use: u64::from(state.outstanding),
                    requested: 1,
                },
            ));
        }
        Ok(candidate)
    }

    pub(super) fn next_class_count(
        state: &AccountingState,
        class: WorkClass,
    ) -> Option<(usize, u32)> {
        let index = class_index(class);
        state
            .class_counts
            .get(index)
            .copied()?
            .checked_add(1)
            .map(|candidate| (index, candidate))
    }
}

fn increment_checked(counter: &AtomicU64) -> Result<(), ()> {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map(|_| ())
        .map_err(|_| ())
}

const fn pressure_index(pressure: DiskPressureState) -> u8 {
    match pressure {
        DiskPressureState::Healthy => 0,
        DiskPressureState::SoftPressure => 1,
        DiskPressureState::HardPressure => 2,
    }
}

const fn pressure_from_index(index: u8) -> DiskPressureState {
    match index {
        1 => DiskPressureState::SoftPressure,
        2 => DiskPressureState::HardPressure,
        _ => DiskPressureState::Healthy,
    }
}
