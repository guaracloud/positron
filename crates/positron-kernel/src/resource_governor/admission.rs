//! Atomic admission planning and commit.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{ReservationIdentity, WorkClaim};
use super::decision::{
    DecisionLimit, OrdinaryCapacity, failure_at_pressure, internal_failure_at_pressure,
    refuse_exceeded, refuse_live_disk_growth, refuse_ordinary_capacity,
    refuse_tenant_recovery_shared_fair_share,
};
use super::failure::{AdmissionFailure, AdmissionFailureCode, AdmissionRetry, LimitingScope};
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
        let tenant_index = Self::tenant_index(state, claim.tenant, class)
            .map_err(|failure| failure.at_pressure(state.disk_pressure))?;
        let outstanding = self.require_healthy_and_slot(state, class, Some(tenant_index))?;
        self.refuse_principal_limit(state, tenant_index, claim.principal, class, claim.amounts)?;
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
        let Some(tenant_limit) = state.tenant_limits.get(tenant_index).copied() else {
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
            state.recovery_tenant_shared_fair.get(tenant_index).copied()
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
        let Some(tenant_fair_capacity) = state.tenant_fair_capacities.get(tenant_index).copied()
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
            principal: claim.principal,
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

    fn refuse_principal_limit(
        &self,
        state: &super::accounting::AccountingState,
        tenant_index: usize,
        principal: Option<positron_domain::identity::PrincipalId>,
        class: super::WorkClass,
        requested: super::ResourceAmounts,
    ) -> Result<(), AdmissionFailure> {
        let Some(principal) = principal else {
            return Ok(());
        };
        let Some(quota) = self.principal_quota else {
            return Ok(());
        };
        let (in_use, usage) = self.principal_usage(state, tenant_index, principal, class)?;
        let allowed = u64::from(quota.maximum_operations());
        if in_use >= allowed {
            return Err(failure_at_pressure(
                AdmissionFailureCode::PrincipalQuotaExceeded,
                AdmissionRetry::AfterCapacityRelease,
                LimitingScope::Principal,
                class,
                state.disk_pressure,
                DecisionLimit {
                    dimension: None,
                    allowed,
                    in_use,
                    requested: 1,
                },
            ));
        }
        refuse_exceeded(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            LimitingScope::Operation,
            class,
            super::ResourceAmounts::zero(),
            requested,
            quota.per_operation_limits(),
            state.disk_pressure,
        )?;
        refuse_exceeded(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            LimitingScope::Principal,
            class,
            usage,
            requested,
            quota.aggregate_limits(),
            state.disk_pressure,
        )?;
        Ok(())
    }

    pub(super) fn refuse_principal_resize_limit(
        &self,
        state: &super::accounting::AccountingState,
        tenant_index: usize,
        principal: Option<positron_domain::identity::PrincipalId>,
        excluded_slot: u16,
        class: super::WorkClass,
        requested: super::ResourceAmounts,
    ) -> Result<(), AdmissionFailure> {
        let Some(principal) = principal else {
            return Ok(());
        };
        let Some(quota) = self.principal_quota else {
            return Ok(());
        };
        let (_, usage) = self.principal_usage_excluding(
            state,
            tenant_index,
            principal,
            Some(excluded_slot),
            class,
        )?;
        refuse_exceeded(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            LimitingScope::Operation,
            class,
            super::ResourceAmounts::zero(),
            requested,
            quota.per_operation_limits(),
            state.disk_pressure,
        )?;
        refuse_exceeded(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            LimitingScope::Principal,
            class,
            usage,
            requested,
            quota.aggregate_limits(),
            state.disk_pressure,
        )
    }

    fn principal_usage(
        &self,
        state: &super::accounting::AccountingState,
        tenant_index: usize,
        principal: positron_domain::identity::PrincipalId,
        class: super::WorkClass,
    ) -> Result<(u64, super::ResourceAmounts), AdmissionFailure> {
        self.principal_usage_excluding(state, tenant_index, principal, None, class)
    }

    fn principal_usage_excluding(
        &self,
        state: &super::accounting::AccountingState,
        tenant_index: usize,
        principal: positron_domain::identity::PrincipalId,
        excluded_slot: Option<u16>,
        class: super::WorkClass,
    ) -> Result<(u64, super::ResourceAmounts), AdmissionFailure> {
        let mut count = 0_u64;
        let mut usage = super::ResourceAmounts::zero();
        for (slot, record) in state.grant_records.iter().enumerate() {
            let slot = u16::try_from(slot)
                .map_err(|_| internal_failure_at_pressure(class, state.disk_pressure))?;
            if Some(slot) == excluded_slot {
                continue;
            }
            let Some(record) = record else {
                continue;
            };
            if record.tenant_index() != Some(tenant_index) || record.principal() != Some(principal)
            {
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            usage = usage
                .checked_add(record.amounts())
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
        }
        Ok((count, usage))
    }
}
