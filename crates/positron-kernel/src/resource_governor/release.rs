//! Exact reservation release with fail-closed invariant handling.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::ReservationIdentity;
use super::failure::GovernorFailure;
use super::lifecycle::{GovernorLifecycle, ReleaseOutcome, class_index};
use super::model::ResourceAmounts;
use super::option_ext::TransposeOption;

pub(super) struct ReleaseStatus {
    pub(super) applied: bool,
    pub(super) result: Result<ReleaseOutcome, GovernorFailure>,
}

impl GovernorInner {
    pub(super) fn try_release(
        &self,
        slot: u16,
        owner: ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
    ) -> ReleaseStatus {
        let (mut state, poisoned) = match self.try_lock_for_control() {
            Ok(guard) => (guard, false),
            Err(GovernorFailure::GovernorContended { .. }) => {
                return ReleaseStatus {
                    applied: false,
                    result: Err(GovernorFailure::GovernorContended {
                        pressure: self.last_pressure(),
                    }),
                };
            },
            Err(GovernorFailure::InternalFenced) => match self.state.try_lock() {
                Ok(guard) => (guard, true),
                Err(_) => {
                    return ReleaseStatus {
                        applied: false,
                        result: Err(GovernorFailure::InternalFenced),
                    };
                },
            },
            Err(other) => {
                return ReleaseStatus {
                    applied: false,
                    result: Err(other),
                };
            },
        };
        let status = self.release_locked(&mut state, poisoned, owner, identity, amounts);
        if status.applied && !self.finish_slot(&mut state, slot) {
            return fence(&mut state);
        }
        status
    }

    pub(super) fn release_locked(
        &self,
        state: &mut super::accounting::AccountingState,
        poisoned: bool,
        owner: ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
    ) -> ReleaseStatus {
        let class = identity.class();
        self.release_components(
            state,
            poisoned,
            owner,
            class,
            matches!(identity, ReservationIdentity::Ordinary { .. }),
            match identity {
                ReservationIdentity::Recovery { kind, .. } => Some(kind),
                ReservationIdentity::Ordinary { .. } => None,
            },
            amounts,
        )
    }

    pub(super) fn release_record_locked(
        &self,
        state: &mut super::accounting::AccountingState,
        record: super::ledger::GrantRecord,
    ) -> ReleaseStatus {
        let Some(owner) = record.owner() else {
            return fence(state);
        };
        self.release_components(
            state,
            false,
            owner,
            record.class(),
            record.is_ordinary(),
            record.recovery_kind(),
            record.amounts(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn release_components(
        &self,
        state: &mut super::accounting::AccountingState,
        poisoned: bool,
        owner: ChargeOwner,
        class: super::WorkClass,
        ordinary: bool,
        recovery_kind: Option<super::RecoveryWorkKind>,
        amounts: ResourceAmounts,
    ) -> ReleaseStatus {
        let Some(total_candidate) = state.total_usage.checked_sub(amounts) else {
            return fence(state);
        };
        let Some(outstanding_candidate) = state.outstanding.checked_sub(1) else {
            return fence(state);
        };
        let index = class_index(class);
        let Some(class_candidate) = state
            .class_counts
            .get(index)
            .copied()
            .and_then(|count| count.checked_sub(1))
        else {
            return fence(state);
        };
        let ordinary_candidate = ordinary
            .then(|| state.outstanding_ordinary.checked_sub(1))
            .flatten();
        let recovery_candidate = (!ordinary)
            .then(|| state.outstanding_recovery.checked_sub(1))
            .flatten();
        let uninterruptible =
            recovery_kind.is_some_and(|kind| kind.retains_capacity_on_resize_failure());
        let uninterruptible_candidate = uninterruptible
            .then(|| state.outstanding_uninterruptible.checked_sub(1))
            .flatten();
        if (ordinary && ordinary_candidate.is_none())
            || (!ordinary && recovery_candidate.is_none())
            || (uninterruptible && uninterruptible_candidate.is_none())
        {
            return fence(state);
        }
        let tenant_index = match owner.attribution {
            ChargeAttribution::Ordinary { tenant_index } => Some(tenant_index),
            ChargeAttribution::Recovery { tenant_index } => tenant_index,
        };
        let tenant_count_candidate = tenant_index
            .map(|index| {
                state
                    .tenant_outstanding
                    .get(index)
                    .copied()
                    .and_then(|count| count.checked_sub(1))
            })
            .transpose_option();
        let Some(tenant_count_candidate) = tenant_count_candidate else {
            return fence(state);
        };

        match owner.attribution {
            ChargeAttribution::Ordinary { tenant_index } => {
                let Some(pools) = owner.pools.map(|charge| charge.capacities()) else {
                    return fence(state);
                };
                let tenant_candidate = state
                    .ordinary_tenant_usage
                    .get(tenant_index)
                    .copied()
                    .and_then(|usage| usage.checked_sub(amounts));
                let tenant_pool_candidate = state
                    .ordinary_tenant_pool_usage
                    .get(tenant_index)
                    .copied()
                    .and_then(|usage| usage.checked_sub(pools));
                let pool_candidate = state.pool_usage.checked_sub(pools);
                let (Some(tenant_candidate), Some(tenant_pool_candidate), Some(pool_candidate)) =
                    (tenant_candidate, tenant_pool_candidate, pool_candidate)
                else {
                    return fence(state);
                };
                let Some(tenant_slot) = state.ordinary_tenant_usage.get_mut(tenant_index) else {
                    return fence(state);
                };
                *tenant_slot = tenant_candidate;
                let Some(tenant_pool_slot) = state.ordinary_tenant_pool_usage.get_mut(tenant_index)
                else {
                    return fence(state);
                };
                *tenant_pool_slot = tenant_pool_candidate;
                state.pool_usage = pool_candidate;
            },
            ChargeAttribution::Recovery { tenant_index } => {
                let Some(pool_charge) = owner.recovery_pools else {
                    return fence(state);
                };
                let Some(accounting_candidate) = state.recovery_usage.checked_sub(amounts) else {
                    return fence(state);
                };
                let Some(pool_candidate) = state.recovery_pool_usage.checked_sub(pool_charge)
                else {
                    return fence(state);
                };
                let tenant_candidate = tenant_index
                    .map(|tenant_index| {
                        state
                            .recovery_tenant_usage
                            .get(tenant_index)
                            .copied()
                            .and_then(|usage| usage.checked_sub(amounts))
                    })
                    .transpose_option();
                let Some(tenant_candidate) = tenant_candidate else {
                    return fence(state);
                };
                if let (Some(index), Some(candidate)) = (tenant_index, tenant_candidate) {
                    let Some(tenant_slot) = state.recovery_tenant_usage.get_mut(index) else {
                        return fence(state);
                    };
                    *tenant_slot = candidate;
                    let Some(pool_slot) = state.recovery_tenant_pool_usage.get_mut(index) else {
                        return fence(state);
                    };
                    let Some(tenant_pool_candidate) = pool_slot.checked_sub(pool_charge) else {
                        return fence(state);
                    };
                    *pool_slot = tenant_pool_candidate;
                } else {
                    let Some(system_candidate) =
                        state.recovery_system_pool_usage.checked_sub(pool_charge)
                    else {
                        return fence(state);
                    };
                    state.recovery_system_pool_usage = system_candidate;
                }
                state.recovery_usage = accounting_candidate;
                state.recovery_pool_usage = pool_candidate;
            },
        }
        state.total_usage = total_candidate;
        state.outstanding = outstanding_candidate;
        let Some(class_slot) = state.class_counts.get_mut(index) else {
            return fence(state);
        };
        *class_slot = class_candidate;
        if let Some(candidate) = ordinary_candidate {
            state.outstanding_ordinary = candidate;
        }
        if let Some(candidate) = recovery_candidate {
            state.outstanding_recovery = candidate;
        }
        if let Some(candidate) = uninterruptible_candidate {
            state.outstanding_uninterruptible = candidate;
        }
        if let (Some(index), Some(candidate)) = (tenant_index, tenant_count_candidate) {
            let Some(slot) = state.tenant_outstanding.get_mut(index) else {
                return fence(state);
            };
            *slot = candidate;
        }
        let fenced = poisoned || state.lifecycle == GovernorLifecycle::Fenced;
        ReleaseStatus {
            applied: true,
            result: if fenced {
                Err(GovernorFailure::InternalFenced)
            } else {
                Ok(ReleaseOutcome::Released)
            },
        }
    }
}

fn fence(state: &mut super::accounting::AccountingState) -> ReleaseStatus {
    state.lifecycle = GovernorLifecycle::Fenced;
    ReleaseStatus {
        applied: false,
        result: Err(GovernorFailure::InternalFenced),
    }
}
