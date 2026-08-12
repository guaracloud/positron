//! Atomic admission for closed recovery work kinds.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{RecoveryScope, RecoveryWorkClaim, ReservationIdentity, WorkClass};
use super::decision::{
    DecisionLimit, failure_at_pressure, internal_failure_at_pressure, refuse_exceeded,
    refuse_live_disk_growth,
};
use super::failure::{AdmissionFailure, AdmissionFailureCode, AdmissionRetry, LimitingScope};
use super::lifecycle::GovernorLifecycle;
use super::pool_admission::shutdown_failure;
use super::recovery_policy::{RecoveryPoolLimit, RecoveryPoolView, plan_recovery_charge};

impl GovernorInner {
    pub(super) fn reserve_recovery(
        &self,
        claim: RecoveryWorkClaim,
    ) -> Result<super::ResourceReservation<'_>, AdmissionFailure> {
        let class = WorkClass::DurabilityRecovery;
        let mut state = self.lock_for_admission(class)?;
        let result = self.reserve_recovery_locked(claim, &mut state);
        if let Err(failure) = &result {
            self.record_refusal_locked(&mut state, failure);
        }
        result
    }

    fn reserve_recovery_locked(
        &self,
        claim: RecoveryWorkClaim,
        state: &mut super::accounting::AccountingState,
    ) -> Result<super::ResourceReservation<'_>, AdmissionFailure> {
        let class = WorkClass::DurabilityRecovery;
        if state.lifecycle == GovernorLifecycle::ShuttingDown
            && !claim.kind.retains_capacity_on_resize_failure()
        {
            return Err(shutdown_failure(class, state.disk_pressure));
        }
        let tenant_index = match claim.scope {
            RecoveryScope::System => None,
            RecoveryScope::Tenant(tenant) => Some(
                self.tenant_index(tenant, class)
                    .map_err(|failure| failure.at_pressure(state.disk_pressure))?,
            ),
        };
        let outstanding = self.require_healthy_and_slot(state, class, tenant_index)?;
        refuse_live_disk_growth(
            class,
            state.total_usage,
            claim.amounts,
            state.usable_disk_bytes,
            state.disk_pressure,
        )?;
        refuse_exceeded(
            AdmissionFailureCode::RecoveryReserveExhausted,
            LimitingScope::RecoveryReserve,
            class,
            state.total_usage,
            claim.amounts,
            self.total_ceiling,
            state.disk_pressure,
        )?;
        let Some(total_candidate) = state.total_usage.checked_add(claim.amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(recovery_candidate) = state.recovery_usage.checked_add(claim.amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(ordinary_usage) = state.total_usage.checked_sub(state.recovery_usage) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let recovery_tenant_candidate = if let Some(index) = tenant_index {
            let Some(usage) = state.recovery_tenant_usage.get(index).copied() else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            let Some(candidate) = usage.checked_add(claim.amounts) else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            let Some(ordinary_usage) = state.ordinary_tenant_usage.get(index).copied() else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            let Some(quota) = self.tenant_quotas.get(index) else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            let combined_usage = ordinary_usage.checked_add(usage).ok_or_else(|| {
                state.lifecycle = GovernorLifecycle::Fenced;
                internal_failure_at_pressure(class, state.disk_pressure)
            })?;
            refuse_exceeded(
                AdmissionFailureCode::TenantQuotaExceeded,
                LimitingScope::Tenant,
                class,
                combined_usage,
                claim.amounts,
                quota.limits,
                state.disk_pressure,
            )?;
            Some(candidate)
        } else {
            None
        };
        let scope = if let Some(index) = tenant_index {
            let shared = self
                .recovery_tenant_shared_fair
                .get(index)
                .copied()
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            let protected = self
                .recovery_tenant_pool_fair
                .get(index)
                .map(|pools| pools.get(claim.kind))
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            let usage = state
                .recovery_tenant_pool_usage
                .get(index)
                .copied()
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            let ordinary = state
                .ordinary_tenant_usage
                .get(index)
                .copied()
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            (shared, protected, usage, ordinary)
        } else {
            (
                self.recovery_shared_capacity,
                self.recovery_system_pool_capacities.get(claim.kind),
                state.recovery_system_pool_usage,
                ordinary_usage,
            )
        };
        let recovery_pools = match plan_recovery_charge(
            claim.kind,
            claim.amounts,
            RecoveryPoolView {
                shared_capacity: self.recovery_shared_capacity,
                protected_capacity: self.recovery_pool_capacities.get(claim.kind),
                usage: state.recovery_pool_usage,
                shared_occupied_by_ordinary: ordinary_usage,
            },
            RecoveryPoolView {
                shared_capacity: scope.0,
                protected_capacity: scope.1,
                usage: scope.2,
                shared_occupied_by_ordinary: scope.3,
            },
        ) {
            Ok(charge) => charge,
            Err(limit) => {
                let failure = recovery_pool_failure(
                    limit,
                    tenant_index.is_some(),
                    claim.kind,
                    claim.amounts,
                    self.recovery_shared_capacity,
                    self.recovery_pool_capacities.get(claim.kind),
                    state.recovery_pool_usage,
                    ordinary_usage,
                    scope,
                    state.disk_pressure,
                );
                if failure.code() == AdmissionFailureCode::InternalFenced {
                    state.lifecycle = GovernorLifecycle::Fenced;
                }
                return Err(failure);
            },
        };
        let recovery_pool_candidate = state
            .recovery_pool_usage
            .checked_add(recovery_pools)
            .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
        let scope_pool_candidate = scope
            .2
            .checked_add(recovery_pools)
            .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
        let Some(recovery_count) = state.outstanding_recovery.checked_add(1) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let uninterruptible_count = if claim.kind.retains_capacity_on_resize_failure() {
            Some(
                state
                    .outstanding_uninterruptible
                    .checked_add(1)
                    .ok_or_else(|| {
                        state.lifecycle = GovernorLifecycle::Fenced;
                        internal_failure_at_pressure(class, state.disk_pressure)
                    })?,
            )
        } else {
            None
        };
        let Some((class_index, class_count)) = Self::next_class_count(state, class) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let recovery_tenant_count = if let Some(index) = tenant_index {
            Some(
                state
                    .tenant_outstanding
                    .get(index)
                    .copied()
                    .and_then(|count| count.checked_add(1))
                    .ok_or_else(|| {
                        state.lifecycle = GovernorLifecycle::Fenced;
                        internal_failure_at_pressure(class, state.disk_pressure)
                    })?,
            )
        } else {
            None
        };
        let owner = ChargeOwner {
            attribution: ChargeAttribution::Recovery { tenant_index },
            pools: None,
            recovery_pools: Some(recovery_pools),
        };
        let identity = ReservationIdentity::Recovery {
            scope: claim.scope,
            kind: claim.kind,
        };
        let Some(record) = super::ledger::GrantRecord::new(owner, identity, claim.amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(reservation_slot) = self.activate_slot(state, record) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        if let (Some(index), Some(candidate)) = (tenant_index, recovery_tenant_candidate) {
            let Some(usage) = state.recovery_tenant_usage.get_mut(index) else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            *usage = candidate;
            let Some(pool_usage) = state.recovery_tenant_pool_usage.get_mut(index) else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            *pool_usage = scope_pool_candidate;
        } else {
            state.recovery_system_pool_usage = scope_pool_candidate;
        }
        if state.class_counts.get(class_index).is_none() {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        }
        state.total_usage = total_candidate;
        state.recovery_usage = recovery_candidate;
        state.recovery_pool_usage = recovery_pool_candidate;
        state.outstanding = outstanding;
        state.outstanding_recovery = recovery_count;
        let Some(class_slot) = state.class_counts.get_mut(class_index) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        *class_slot = class_count;
        if let (Some(index), Some(count)) = (tenant_index, recovery_tenant_count) {
            let Some(slot) = state.tenant_outstanding.get_mut(index) else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            *slot = count;
        }
        if let Some(count) = uninterruptible_count {
            state.outstanding_uninterruptible = count;
        }
        Ok(super::ResourceReservation::new(
            self,
            owner,
            identity,
            claim.amounts,
            reservation_slot,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn recovery_pool_failure(
    limit: RecoveryPoolLimit,
    tenant: bool,
    kind: super::RecoveryWorkKind,
    requested: super::ResourceAmounts,
    global_shared: super::ResourceAmounts,
    global_protected: super::ResourceAmounts,
    global_usage: super::recovery_policy::RecoveryPoolUsage,
    global_shared_occupied_by_ordinary: super::ResourceAmounts,
    scope: (
        super::ResourceAmounts,
        super::ResourceAmounts,
        super::recovery_policy::RecoveryPoolUsage,
        super::ResourceAmounts,
    ),
    pressure: super::DiskPressureState,
) -> AdmissionFailure {
    let dimension = match limit {
        RecoveryPoolLimit::Global(dimension) | RecoveryPoolLimit::Scope(dimension) => dimension,
        RecoveryPoolLimit::Internal => {
            return internal_failure_at_pressure(WorkClass::DurabilityRecovery, pressure);
        },
    };
    let scope_limited = matches!(limit, RecoveryPoolLimit::Scope(_));
    let (shared, protected, pool_usage, shared_occupied_by_ordinary) = if scope_limited {
        scope
    } else {
        (
            global_shared,
            global_protected,
            global_usage,
            global_shared_occupied_by_ordinary,
        )
    };
    let allowed = shared.get(dimension).checked_add(protected.get(dimension));
    let in_use = pool_usage
        .shared()
        .get(dimension)
        .checked_add(shared_occupied_by_ordinary.get(dimension))
        .and_then(|usage| usage.checked_add(pool_usage.protected(kind).get(dimension)));
    let (Some(allowed), Some(in_use)) = (allowed, in_use) else {
        return internal_failure_at_pressure(WorkClass::DurabilityRecovery, pressure);
    };
    failure_at_pressure(
        if scope_limited {
            if tenant {
                AdmissionFailureCode::TenantFairShareExceeded
            } else {
                AdmissionFailureCode::ProtectedCapacityUnavailable
            }
        } else {
            AdmissionFailureCode::RecoveryReserveExhausted
        },
        AdmissionRetry::AfterCapacityRelease,
        if scope_limited {
            if tenant {
                LimitingScope::TenantFairShare
            } else {
                LimitingScope::ProtectedReserve
            }
        } else {
            LimitingScope::RecoveryReserve
        },
        WorkClass::DurabilityRecovery,
        pressure,
        DecisionLimit {
            dimension: Some(dimension),
            allowed,
            in_use,
            requested: requested.get(dimension),
        },
    )
}
