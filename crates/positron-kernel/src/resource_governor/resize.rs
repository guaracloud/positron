//! Atomic runtime reservation correction.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{ReservationIdentity, WorkClass};
use super::decision::{
    OrdinaryCapacity, internal_failure_at_pressure, refuse_exceeded, refuse_live_disk_growth,
    refuse_ordinary_capacity, refuse_tenant_recovery_shared_fair_share,
};
use super::failure::{AdmissionFailure, AdmissionFailureCode, DiskPressureState, LimitingScope};
use super::lifecycle::{GovernorLifecycle, class_index};
use super::model::{ResourceAmounts, ResourceDimension};
use super::pool_admission::{
    PoolAdmission, plan_pool_charge, pressure_eligibility, shutdown_failure,
};
use super::resize_types::{
    ExistingCapacityDisposition, ResizeCommit, ResizeFailure, ResizeFailureCode, ResizeOutcome,
};

#[derive(Clone, Copy)]
pub(super) struct ResizeRequest {
    pub(super) slot: u16,
    pub(super) owner: ChargeOwner,
    pub(super) identity: ReservationIdentity,
    pub(super) old: ResourceAmounts,
    pub(super) new: ResourceAmounts,
}

impl GovernorInner {
    pub(super) fn resize(&self, request: ResizeRequest) -> Result<ResizeCommit, ResizeFailure> {
        match request.identity {
            ReservationIdentity::Ordinary { tenant, kind } => {
                let class = kind.class();
                let ChargeAttribution::Ordinary { tenant_index } = request.owner.attribution else {
                    return Err(retained_resize(class, self.pressure_for_failure()));
                };
                let _ = tenant;
                self.resize_ordinary(request, tenant_index, class)
            },
            ReservationIdentity::Recovery { scope, kind } => {
                let ChargeAttribution::Recovery { tenant_index } = request.owner.attribution else {
                    return Err(retained_resize(
                        WorkClass::DurabilityRecovery,
                        self.pressure_for_failure(),
                    ));
                };
                let _ = scope;
                self.resize_recovery(request, tenant_index, kind)
            },
        }
    }

    fn resize_ordinary(
        &self,
        request: ResizeRequest,
        tenant_index: usize,
        class: WorkClass,
    ) -> Result<ResizeCommit, ResizeFailure> {
        let mut state = self.lock_for_admission(class).map_err(|failure| {
            ResizeFailure::admission(failure, ExistingCapacityDisposition::CapacityRetained)
        })?;
        let result = self.resize_ordinary_locked(request, tenant_index, class, &mut state);
        if let Err(failure) = &result
            && let Some(admission) = failure.admission_failure()
        {
            self.record_refusal_locked(&mut state, &admission);
        }
        result
    }

    fn resize_ordinary_locked(
        &self,
        request: ResizeRequest,
        tenant_index: usize,
        class: WorkClass,
        state: &mut super::accounting::AccountingState,
    ) -> Result<ResizeCommit, ResizeFailure> {
        let ResizeRequest {
            slot,
            owner,
            identity,
            old,
            new,
        } = request;
        if state.lifecycle == GovernorLifecycle::Fenced {
            return Err(retained_resize(class, state.disk_pressure));
        }
        let Some(old_pools) = owner.pools else {
            return Err(fence_resize(state, class));
        };
        let old_pool_amounts = old_pools.capacities();
        let Some(total_without) = state.total_usage.checked_sub(old) else {
            return Err(fence_resize(state, class));
        };
        let Some(tenant_without) = state
            .ordinary_tenant_usage
            .get(tenant_index)
            .copied()
            .and_then(|usage| usage.checked_sub(old))
        else {
            return Err(fence_resize(state, class));
        };
        let Some(pool_without) = state.pool_usage.checked_sub(old_pool_amounts) else {
            return Err(fence_resize(state, class));
        };
        let Some(tenant_pool_without) = state
            .ordinary_tenant_pool_usage
            .get(tenant_index)
            .copied()
            .and_then(|usage| usage.checked_sub(old_pool_amounts))
        else {
            return Err(fence_resize(state, class));
        };

        let planned = if new.is_at_most(old) {
            // This is the sole `shrink_to` call site, so the helper can focus
            // on preserving the existing pool attribution exactly.
            old_pools.shrink_to(new).ok_or_else(|| {
                ResizeFailure::admission(
                    internal_failure_at_pressure(class, state.disk_pressure),
                    ExistingCapacityDisposition::CapacityRetained,
                )
            })
        } else {
            let live_disk = if new.get(ResourceDimension::DiskHeadroomBytes)
                > old.get(ResourceDimension::DiskHeadroomBytes)
            {
                refuse_live_disk_growth(
                    class,
                    total_without,
                    new,
                    state.usable_disk_bytes,
                    state.disk_pressure,
                )
            } else {
                Ok(())
            };
            live_disk
                .and_then(|()| {
                    let recovery_shared_usage = state
                        .recovery_tenant_pool_usage
                        .get(tenant_index)
                        .map(|usage| usage.shared())
                        .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
                    self.plan_ordinary_resize(
                        class,
                        new,
                        OrdinaryResizeView {
                            total_without,
                            tenant_without,
                            pool_without,
                            tenant_pool_without,
                            recovery_usage: state.recovery_usage,
                            recovery_shared_usage: state.recovery_pool_usage.shared(),
                            recovery_tenant_shared_usage: recovery_shared_usage,
                            pressure: state.disk_pressure,
                            lifecycle: state.lifecycle,
                            tenant_index,
                        },
                    )
                })
                .map_err(|failure| {
                    ResizeFailure::admission(
                        failure,
                        ExistingCapacityDisposition::CancelledBeforeLimit,
                    )
                })
        };
        let new_pools = match planned {
            Ok(pools) => pools,
            Err(failure) if failure.code == ResizeFailureCode::AdmissionRefused => {
                let Some(outstanding) = state.outstanding.checked_sub(1) else {
                    return Err(fence_resize(state, class));
                };
                let Some(ordinary) = state.outstanding_ordinary.checked_sub(1) else {
                    return Err(fence_resize(state, class));
                };
                let Some(tenant_count) = state
                    .tenant_outstanding
                    .get(tenant_index)
                    .copied()
                    .and_then(|count| count.checked_sub(1))
                else {
                    return Err(fence_resize(state, class));
                };
                let index = class_index(class);
                let Some(class_count) = state
                    .class_counts
                    .get(index)
                    .copied()
                    .and_then(|count| count.checked_sub(1))
                else {
                    return Err(fence_resize(state, class));
                };
                if !replace_at(
                    &mut state.ordinary_tenant_usage,
                    tenant_index,
                    tenant_without,
                ) || !replace_at(
                    &mut state.ordinary_tenant_pool_usage,
                    tenant_index,
                    tenant_pool_without,
                ) || !replace_at(&mut state.class_counts, index, class_count)
                    || !replace_at(&mut state.tenant_outstanding, tenant_index, tenant_count)
                {
                    return Err(fence_resize(state, class));
                }
                state.total_usage = total_without;
                state.pool_usage = pool_without;
                state.outstanding = outstanding;
                state.outstanding_ordinary = ordinary;
                if !self.finish_slot(state, slot) {
                    return Err(fence_resize(state, class));
                }
                return Err(failure);
            },
            Err(failure) => {
                if failure.code == ResizeFailureCode::InternalFenced {
                    state.lifecycle = GovernorLifecycle::Fenced;
                }
                return Err(failure);
            },
        };
        let new_pool_amounts = new_pools.capacities();
        let Some(total_candidate) = total_without.checked_add(new) else {
            return Err(fence_resize(state, class));
        };
        let Some(tenant_candidate) = tenant_without.checked_add(new) else {
            return Err(fence_resize(state, class));
        };
        let Some(pool_candidate) = pool_without.checked_add(new_pool_amounts) else {
            return Err(fence_resize(state, class));
        };
        let Some(tenant_pool_candidate) = tenant_pool_without.checked_add(new_pool_amounts) else {
            return Err(fence_resize(state, class));
        };
        if !replace_at(
            &mut state.ordinary_tenant_usage,
            tenant_index,
            tenant_candidate,
        ) || !replace_at(
            &mut state.ordinary_tenant_pool_usage,
            tenant_index,
            tenant_pool_candidate,
        ) {
            return Err(fence_resize(state, class));
        }
        state.total_usage = total_candidate;
        state.pool_usage = pool_candidate;
        let updated_owner = ChargeOwner {
            attribution: owner.attribution,
            pools: Some(new_pools),
            recovery_pools: None,
        };
        if !self.replace_slot_record(state, slot, updated_owner, identity, new) {
            return Err(fence_resize(state, class));
        }
        Ok(ResizeCommit {
            owner: updated_owner,
            outcome: resize_outcome(old, new),
        })
    }

    fn plan_ordinary_resize(
        &self,
        class: WorkClass,
        new: ResourceAmounts,
        view: OrdinaryResizeView,
    ) -> Result<super::policy::PoolCharge, AdmissionFailure> {
        if view.lifecycle == GovernorLifecycle::ShuttingDown {
            return Err(shutdown_failure(class, view.pressure));
        }
        let ordinary_without = view
            .total_without
            .checked_sub(view.recovery_usage)
            .ok_or_else(|| internal_failure_at_pressure(class, view.pressure))?;
        refuse_ordinary_capacity(
            class,
            new,
            OrdinaryCapacity {
                ordinary_usage: ordinary_without,
                recovery_shared_usage: view.recovery_shared_usage,
                ordinary_ceiling: self.ordinary_ceiling,
                total_ceiling: self.total_ceiling,
                pressure: view.pressure,
            },
        )?;
        let tenant_limit = self
            .tenant_quotas
            .get(view.tenant_index)
            .map(|quota| quota.limits)
            .ok_or_else(|| internal_failure_at_pressure(class, view.pressure))?;
        refuse_exceeded(
            AdmissionFailureCode::TenantQuotaExceeded,
            LimitingScope::Tenant,
            class,
            view.tenant_without,
            new,
            tenant_limit,
            view.pressure,
        )?;
        let recovery_shared_limit = self
            .recovery_tenant_shared_fair
            .get(view.tenant_index)
            .copied()
            .ok_or_else(|| internal_failure_at_pressure(class, view.pressure))?;
        refuse_tenant_recovery_shared_fair_share(
            class,
            view.tenant_without,
            view.recovery_tenant_shared_usage,
            new,
            recovery_shared_limit,
            view.pressure,
        )?;
        let shared = pressure_eligibility(view.pressure, class, new)?;
        let tenant_capacity = self
            .tenant_fair_capacities
            .get(view.tenant_index)
            .copied()
            .ok_or_else(|| internal_failure_at_pressure(class, view.pressure))?;
        plan_pool_charge(
            class,
            new,
            PoolAdmission {
                global_capacity: self.pool_capacities,
                global_usage: view.pool_without,
                tenant_capacity,
                tenant_usage: view.tenant_pool_without,
            },
            view.pressure,
            shared,
        )
    }
}

struct OrdinaryResizeView {
    total_without: ResourceAmounts,
    tenant_without: ResourceAmounts,
    pool_without: super::policy::PoolCapacities,
    tenant_pool_without: super::policy::PoolCapacities,
    recovery_usage: ResourceAmounts,
    recovery_shared_usage: ResourceAmounts,
    recovery_tenant_shared_usage: ResourceAmounts,
    pressure: DiskPressureState,
    lifecycle: GovernorLifecycle,
    tenant_index: usize,
}

pub(super) fn resize_outcome(old: ResourceAmounts, new: ResourceAmounts) -> ResizeOutcome {
    ResizeOutcome {
        released: old.excess_over(new),
        added: new.excess_over(old),
    }
}

pub(super) fn retained_resize(class: WorkClass, pressure: DiskPressureState) -> ResizeFailure {
    ResizeFailure::admission(
        internal_failure_at_pressure(class, pressure),
        ExistingCapacityDisposition::CapacityRetained,
    )
}

pub(super) fn fence_resize(
    state: &mut super::accounting::AccountingState,
    class: WorkClass,
) -> ResizeFailure {
    state.lifecycle = GovernorLifecycle::Fenced;
    retained_resize(class, state.disk_pressure)
}

pub(super) fn replace_at<T>(values: &mut [T], index: usize, value: T) -> bool {
    let Some(slot) = values.get_mut(index) else {
        return false;
    };
    *slot = value;
    true
}
