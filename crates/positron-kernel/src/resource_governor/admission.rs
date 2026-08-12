//! Atomic admission planning and commit.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{ReservationIdentity, WorkClaim};
use super::decision::{
    OrdinaryCapacity, internal_failure_at_pressure, refuse_exceeded, refuse_live_disk_growth,
    refuse_ordinary_capacity, refuse_tenant_recovery_shared_fair_share,
};
use super::failure::{AdmissionFailure, AdmissionFailureCode, LimitingScope};
use super::lifecycle::GovernorLifecycle;
use super::pool_admission::{
    PoolAdmission, plan_pool_charge, pressure_eligibility, shutdown_failure,
};

impl GovernorInner {
    pub(super) fn reserve_ordinary(
        &self,
        claim: WorkClaim,
    ) -> Result<super::ResourceReservation<'_>, AdmissionFailure> {
        let class = claim.class();
        let mut state = self.lock_for_admission(class)?;
        let result = self.reserve_ordinary_locked(claim, &mut state);
        if let Err(failure) = &result {
            self.record_refusal_locked(&mut state, failure);
        }
        result
    }

    fn reserve_ordinary_locked(
        &self,
        claim: WorkClaim,
        state: &mut super::accounting::AccountingState,
    ) -> Result<super::ResourceReservation<'_>, AdmissionFailure> {
        let class = claim.class();
        if state.lifecycle == GovernorLifecycle::ShuttingDown {
            return Err(shutdown_failure(class, state.disk_pressure));
        }
        let tenant_index = self
            .tenant_index(claim.tenant, class)
            .map_err(|failure| failure.at_pressure(state.disk_pressure))?;
        let outstanding = self.require_healthy_and_slot(state, class, Some(tenant_index))?;
        let shared_eligible = pressure_eligibility(state.disk_pressure, class, claim.amounts)?;
        refuse_live_disk_growth(
            class,
            state.total_usage,
            claim.amounts,
            state.usable_disk_bytes,
            state.disk_pressure,
        )?;
        let Some(ordinary_usage) = state.total_usage.checked_sub(state.recovery_usage) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        refuse_ordinary_capacity(
            class,
            claim.amounts,
            OrdinaryCapacity {
                ordinary_usage,
                recovery_shared_usage: state.recovery_pool_usage.shared(),
                ordinary_ceiling: self.ordinary_ceiling,
                total_ceiling: self.total_ceiling,
                pressure: state.disk_pressure,
            },
        )?;
        let Some(total_candidate) = state.total_usage.checked_add(claim.amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(tenant_usage) = state.ordinary_tenant_usage.get(tenant_index).copied() else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(tenant_limit) = self
            .tenant_quotas
            .get(tenant_index)
            .map(|quota| quota.limits)
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        refuse_exceeded(
            AdmissionFailureCode::TenantQuotaExceeded,
            LimitingScope::Tenant,
            class,
            tenant_usage,
            claim.amounts,
            tenant_limit,
            state.disk_pressure,
        )?;
        let Some(recovery_shared_usage) = state
            .recovery_tenant_pool_usage
            .get(tenant_index)
            .map(|usage| usage.shared())
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(recovery_shared_limit) =
            self.recovery_tenant_shared_fair.get(tenant_index).copied()
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let combined_fairness = refuse_tenant_recovery_shared_fair_share(
            class,
            tenant_usage,
            recovery_shared_usage,
            claim.amounts,
            recovery_shared_limit,
            state.disk_pressure,
        );
        if let Err(failure) = combined_fairness {
            if failure.code() == AdmissionFailureCode::InternalFenced {
                state.lifecycle = GovernorLifecycle::Fenced;
            }
            return Err(failure);
        }
        let Some(tenant_candidate) = tenant_usage.checked_add(claim.amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(tenant_pool_usage) = state.ordinary_tenant_pool_usage.get(tenant_index).copied()
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(tenant_fair_capacity) = self.tenant_fair_capacities.get(tenant_index).copied()
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let pools = match plan_pool_charge(
            class,
            claim.amounts,
            PoolAdmission {
                global_capacity: self.pool_capacities,
                global_usage: state.pool_usage,
                tenant_capacity: tenant_fair_capacity,
                tenant_usage: tenant_pool_usage,
            },
            state.disk_pressure,
            shared_eligible,
        ) {
            Ok(pools) => pools,
            Err(failure) => {
                if failure.code() == AdmissionFailureCode::InternalFenced {
                    state.lifecycle = GovernorLifecycle::Fenced;
                }
                return Err(failure);
            },
        };
        let pool_amounts = pools.capacities();
        let Some(pool_candidate) = state.pool_usage.checked_add(pool_amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(tenant_pool_candidate) = tenant_pool_usage.checked_add(pool_amounts) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(ordinary_count) = state.outstanding_ordinary.checked_add(1) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some((class_index, class_count)) = Self::next_class_count(state, class) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(tenant_count) = state
            .tenant_outstanding
            .get(tenant_index)
            .copied()
            .and_then(|count| count.checked_add(1))
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        if state.ordinary_tenant_usage.get(tenant_index).is_none()
            || state.ordinary_tenant_pool_usage.get(tenant_index).is_none()
            || state.class_counts.get(class_index).is_none()
            || state.tenant_outstanding.get(tenant_index).is_none()
        {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        }
        let owner = ChargeOwner {
            attribution: ChargeAttribution::Ordinary { tenant_index },
            pools: Some(pools),
            recovery_pools: None,
        };
        let identity = ReservationIdentity::Ordinary {
            tenant: claim.tenant,
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
        let Some(tenant_usage_slot) = state.ordinary_tenant_usage.get_mut(tenant_index) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        *tenant_usage_slot = tenant_candidate;
        let Some(tenant_pool_slot) = state.ordinary_tenant_pool_usage.get_mut(tenant_index) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        *tenant_pool_slot = tenant_pool_candidate;
        let Some(class_slot) = state.class_counts.get_mut(class_index) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        *class_slot = class_count;
        let Some(tenant_count_slot) = state.tenant_outstanding.get_mut(tenant_index) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        *tenant_count_slot = tenant_count;
        state.total_usage = total_candidate;
        state.pool_usage = pool_candidate;
        state.outstanding = outstanding;
        state.outstanding_ordinary = ordinary_count;
        Ok(super::ResourceReservation::new(
            self,
            owner,
            identity,
            claim.amounts,
            reservation_slot,
        ))
    }
}
