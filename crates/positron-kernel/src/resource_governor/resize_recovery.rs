//! Recovery reservation replacement and interruption semantics.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{RecoveryWorkKind, WorkClass};
use super::decision::{internal_failure_at_pressure, refuse_exceeded, refuse_live_disk_growth};
use super::failure::{AdmissionFailureCode, LimitingScope};
use super::lifecycle::{GovernorLifecycle, class_index};
use super::model::ResourceDimension;
use super::option_ext::TransposeOption;
use super::pool_admission::shutdown_failure;
use super::recovery_admission::recovery_pool_failure;
use super::recovery_policy::{RecoveryPoolView, plan_recovery_charge};
use super::resize::{ResizeRequest, fence_resize, replace_at, resize_outcome, retained_resize};
use super::resize_types::{ExistingCapacityDisposition, ResizeCommit, ResizeFailure};

impl GovernorInner {
    pub(super) fn resize_recovery(
        &self,
        request: ResizeRequest,
        tenant_index: Option<usize>,
        kind: RecoveryWorkKind,
    ) -> Result<ResizeCommit, ResizeFailure> {
        let class = WorkClass::DurabilityRecovery;
        let mut state = self.lock_for_admission(class).map_err(|failure| {
            ResizeFailure::admission(failure, ExistingCapacityDisposition::CapacityRetained)
        })?;
        let result = self.resize_recovery_locked(request, tenant_index, kind, &mut state);
        if let Err(failure) = &result
            && let Some(admission) = failure.admission_failure()
        {
            self.record_refusal_locked(&mut state, &admission);
        }
        result
    }

    fn resize_recovery_locked(
        &self,
        request: ResizeRequest,
        tenant_index: Option<usize>,
        kind: RecoveryWorkKind,
        state: &mut super::accounting::AccountingState,
    ) -> Result<ResizeCommit, ResizeFailure> {
        let ResizeRequest {
            slot,
            owner,
            identity,
            old,
            new,
            preserve_existing,
        } = request;
        let class = WorkClass::DurabilityRecovery;
        if state.lifecycle == GovernorLifecycle::Fenced {
            return Err(retained_resize(class, state.disk_pressure));
        }
        let Some(old_pool_charge) = owner.recovery_pools else {
            return Err(fence_resize(state, class));
        };
        let Some(total_without) = state.total_usage.checked_sub(old) else {
            return Err(fence_resize(state, class));
        };
        let Some(recovery_without) = state.recovery_usage.checked_sub(old) else {
            return Err(fence_resize(state, class));
        };
        let Some(ordinary_usage) = total_without.checked_sub(recovery_without) else {
            return Err(fence_resize(state, class));
        };
        let Some(recovery_candidate) = recovery_without.checked_add(new) else {
            return Err(fence_resize(state, class));
        };
        let Some(pool_without) = state.recovery_pool_usage.checked_sub(old_pool_charge) else {
            return Err(fence_resize(state, class));
        };
        let scope_usage = if let Some(index) = tenant_index {
            state
                .recovery_tenant_pool_usage
                .get(index)
                .copied()
                .and_then(|usage| usage.checked_sub(old_pool_charge))
        } else {
            state
                .recovery_system_pool_usage
                .checked_sub(old_pool_charge)
        };
        let Some(scope_without) = scope_usage else {
            return Err(fence_resize(state, class));
        };
        let tenant_without = tenant_index
            .map(|index| {
                state
                    .recovery_tenant_usage
                    .get(index)
                    .copied()
                    .and_then(|usage| usage.checked_sub(old))
            })
            .transpose_option();
        let Some(tenant_without) = tenant_without else {
            return Err(fence_resize(state, class));
        };
        let tenant_candidate = tenant_without
            .map(|usage| usage.checked_add(new))
            .transpose_option();
        let Some(tenant_candidate) = tenant_candidate else {
            return Err(fence_resize(state, class));
        };
        let mut planned_pools = None;
        let admission =
            if state.lifecycle == GovernorLifecycle::ShuttingDown
                && !kind.retains_capacity_on_resize_failure()
                && !new.is_at_most(old)
            {
                Err(shutdown_failure(class, state.disk_pressure))
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
                        if let (Some(index), Some(recovery_without)) =
                            (tenant_index, tenant_without)
                        {
                            let ordinary =
                                state.ordinary_tenant_usage.get(index).copied().ok_or_else(
                                    || internal_failure_at_pressure(class, state.disk_pressure),
                                )?;
                            let quota = self.tenant_quotas.get(index).ok_or_else(|| {
                                internal_failure_at_pressure(class, state.disk_pressure)
                            })?;
                            let combined_without =
                                ordinary.checked_add(recovery_without).ok_or_else(|| {
                                    internal_failure_at_pressure(class, state.disk_pressure)
                                })?;
                            // Resize evidence reports the complete replacement
                            // claim as requested, consistently with ordinary
                            // replacement admission.
                            refuse_exceeded(
                                AdmissionFailureCode::TenantQuotaExceeded,
                                LimitingScope::Tenant,
                                class,
                                combined_without,
                                new,
                                quota.limits,
                                state.disk_pressure,
                            )?;
                        }
                        Ok(())
                    })
                    .and_then(|()| {
                        let scope_capacity = if let Some(index) = tenant_index {
                            (
                                self.recovery_tenant_shared_fair
                                    .get(index)
                                    .copied()
                                    .ok_or_else(|| {
                                        internal_failure_at_pressure(class, state.disk_pressure)
                                    })?,
                                self.recovery_tenant_pool_fair
                                    .get(index)
                                    .map(|pools| pools.get(kind))
                                    .ok_or_else(|| {
                                        internal_failure_at_pressure(class, state.disk_pressure)
                                    })?,
                                state.ordinary_tenant_usage.get(index).copied().ok_or_else(
                                    || internal_failure_at_pressure(class, state.disk_pressure),
                                )?,
                            )
                        } else {
                            (
                                self.recovery_shared_capacity,
                                self.recovery_system_pool_capacities.get(kind),
                                ordinary_usage,
                            )
                        };
                        let charge = plan_recovery_charge(
                            kind,
                            new,
                            RecoveryPoolView {
                                shared_capacity: self.recovery_shared_capacity,
                                protected_capacity: self.recovery_pool_capacities.get(kind),
                                usage: pool_without,
                                shared_occupied_by_ordinary: ordinary_usage,
                            },
                            RecoveryPoolView {
                                shared_capacity: scope_capacity.0,
                                protected_capacity: scope_capacity.1,
                                usage: scope_without,
                                shared_occupied_by_ordinary: scope_capacity.2,
                            },
                        )
                        .map_err(|limit| {
                            recovery_pool_failure(
                                limit,
                                tenant_index.is_some(),
                                kind,
                                new,
                                self.recovery_shared_capacity,
                                self.recovery_pool_capacities.get(kind),
                                pool_without,
                                ordinary_usage,
                                (
                                    scope_capacity.0,
                                    scope_capacity.1,
                                    scope_without,
                                    scope_capacity.2,
                                ),
                                state.disk_pressure,
                            )
                        })?;
                        planned_pools = Some(charge);
                        Ok(())
                    })
                    .and_then(|()| {
                        refuse_exceeded(
                            AdmissionFailureCode::RecoveryReserveExhausted,
                            LimitingScope::RecoveryReserve,
                            class,
                            total_without,
                            new,
                            self.total_ceiling,
                            state.disk_pressure,
                        )
                    })
            };
        if let Err(admission) = admission {
            let retain = preserve_existing || kind.retains_capacity_on_resize_failure();
            if !retain {
                let Some(outstanding) = state.outstanding.checked_sub(1) else {
                    return Err(fence_resize(state, class));
                };
                let Some(recovery_count) = state.outstanding_recovery.checked_sub(1) else {
                    return Err(fence_resize(state, class));
                };
                let tenant_count = tenant_index
                    .map(|index| {
                        state
                            .tenant_outstanding
                            .get(index)
                            .copied()
                            .and_then(|count| count.checked_sub(1))
                    })
                    .transpose_option();
                let Some(tenant_count) = tenant_count else {
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
                state.total_usage = total_without;
                state.recovery_usage = recovery_without;
                state.recovery_pool_usage = pool_without;
                if let (Some(index), Some(usage)) = (tenant_index, tenant_without)
                    && !replace_at(&mut state.recovery_tenant_usage, index, usage)
                {
                    return Err(fence_resize(state, class));
                }
                if let Some(index) = tenant_index {
                    if !replace_at(&mut state.recovery_tenant_pool_usage, index, scope_without) {
                        return Err(fence_resize(state, class));
                    }
                } else {
                    state.recovery_system_pool_usage = scope_without;
                }
                state.outstanding = outstanding;
                state.outstanding_recovery = recovery_count;
                if !replace_at(&mut state.class_counts, index, class_count) {
                    return Err(fence_resize(state, class));
                }
                if let (Some(index), Some(count)) = (tenant_index, tenant_count)
                    && !replace_at(&mut state.tenant_outstanding, index, count)
                {
                    return Err(fence_resize(state, class));
                }
                if !self.finish_slot(state, slot) {
                    return Err(fence_resize(state, class));
                }
            }
            return Err(ResizeFailure::admission(
                admission,
                if retain {
                    ExistingCapacityDisposition::CapacityRetained
                } else {
                    ExistingCapacityDisposition::CancelledBeforeLimit
                },
            ));
        }
        let Some(total_candidate) = total_without.checked_add(new) else {
            return Err(fence_resize(state, class));
        };
        let Some(new_pool_charge) = planned_pools else {
            return Err(fence_resize(state, class));
        };
        let Some(pool_candidate) = pool_without.checked_add(new_pool_charge) else {
            return Err(fence_resize(state, class));
        };
        let Some(scope_candidate) = scope_without.checked_add(new_pool_charge) else {
            return Err(fence_resize(state, class));
        };
        state.total_usage = total_candidate;
        state.recovery_usage = recovery_candidate;
        state.recovery_pool_usage = pool_candidate;
        if let (Some(index), Some(usage)) = (tenant_index, tenant_candidate)
            && !replace_at(&mut state.recovery_tenant_usage, index, usage)
        {
            return Err(fence_resize(state, class));
        }
        if let Some(index) = tenant_index {
            if !replace_at(
                &mut state.recovery_tenant_pool_usage,
                index,
                scope_candidate,
            ) {
                return Err(fence_resize(state, class));
            }
        } else {
            state.recovery_system_pool_usage = scope_candidate;
        }
        let updated_owner = ChargeOwner {
            attribution: ChargeAttribution::Recovery { tenant_index },
            pools: None,
            recovery_pools: Some(new_pool_charge),
        };
        if !self.replace_slot_record(state, slot, updated_owner, identity, new) {
            return Err(fence_resize(state, class));
        }
        Ok(ResizeCommit {
            owner: updated_owner,
            outcome: resize_outcome(old, new),
        })
    }
}
