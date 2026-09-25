//! Atomic admission planning and commit.

use super::accounting::{ChargeAttribution, ChargeOwner, GovernorInner};
use super::claim::{OperationToken, ReservationIdentity, WorkClaim};
use super::decision::{
    DecisionLimit, OrdinaryCapacity, failure_at_pressure, internal_failure_at_pressure,
    refuse_exceeded, refuse_live_disk_growth, refuse_ordinary_capacity,
    refuse_tenant_recovery_shared_fair_share,
};
use super::failure::{AdmissionFailure, AdmissionFailureCode, AdmissionRetry, LimitingScope};
use super::ledger::OperationRecord;
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
        self.validate_operation_child(state, tenant_index, claim.operation, class)?;
        self.refuse_principal_limit(
            state,
            tenant_index,
            claim.principal,
            claim.operation,
            class,
            claim.amounts,
        )?;
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
        let operation =
            self.operation_record_for_claim(state, claim.operation, claim.principal, class)?;
        let Some(record) =
            super::ledger::GrantRecord::new(owner, identity, claim.amounts, operation)
        else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        let Some(reservation_slot) = self.activate_slot(state, record) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        if let Some(OperationToken { root_slot, .. }) = claim.operation {
            let Some(root) = state
                .grant_records
                .get_mut(usize::from(root_slot))
                .and_then(|record| record.as_mut())
            else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            let Some(updated) = root.increment_root_child() else {
                state.lifecycle = GovernorLifecycle::Fenced;
                return Err(internal_failure_at_pressure(class, state.disk_pressure));
            };
            *root = updated;
        }
        let reservation_operation = state
            .grant_records
            .get(usize::from(reservation_slot))
            .and_then(|record| *record)
            .and_then(|record| record.root_token(reservation_slot));
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
            reservation_operation,
        ))
    }

    fn refuse_principal_limit(
        &self,
        state: &super::accounting::AccountingState,
        tenant_index: usize,
        principal: Option<positron_domain::identity::PrincipalId>,
        operation: Option<OperationToken>,
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
        if operation.is_none() && in_use >= allowed {
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
        let operation_usage = match operation {
            Some(token) => self.operation_usage(state, token, None, class)?,
            None => super::ResourceAmounts::zero(),
        };
        refuse_exceeded(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            LimitingScope::Operation,
            class,
            operation_usage,
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
        let operation = state
            .grant_records
            .get(usize::from(excluded_slot))
            .and_then(|record| *record)
            .and_then(|record| match record.operation() {
                Some(OperationRecord::Root { generation, .. }) => Some(OperationToken {
                    root_slot: excluded_slot,
                    generation,
                    tenant: match record.root_token(excluded_slot) {
                        Some(token) => token.tenant,
                        None => return None,
                    },
                    principal,
                    kind: match record.root_token(excluded_slot) {
                        Some(token) => token.kind,
                        None => return None,
                    },
                }),
                Some(OperationRecord::Child {
                    root_slot,
                    generation,
                }) => state
                    .grant_records
                    .get(usize::from(root_slot))
                    .and_then(|root| *root)
                    .and_then(|root| root.root_token(root_slot))
                    .filter(|token| token.generation == generation),
                None => None,
            });
        let operation_usage = match operation {
            Some(token) => self.operation_usage(state, token, Some(excluded_slot), class)?,
            None => super::ResourceAmounts::zero(),
        };
        refuse_exceeded(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            LimitingScope::Operation,
            class,
            operation_usage,
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
            if record.is_operation_root() {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            }
            usage = usage
                .checked_add(record.amounts())
                .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
        }
        Ok((count, usage))
    }

    fn validate_operation_child(
        &self,
        state: &super::accounting::AccountingState,
        tenant_index: usize,
        operation: Option<OperationToken>,
        class: super::WorkClass,
    ) -> Result<(), AdmissionFailure> {
        let Some(token) = operation else {
            return Ok(());
        };
        let valid = state
            .grant_records
            .get(usize::from(token.root_slot))
            .and_then(|record| *record)
            .is_some_and(|record| {
                record.tenant_index() == Some(tenant_index)
                    && record.tenant() == Some(token.tenant)
                    && record.principal() == Some(token.principal)
                    && record.class() == class
                    && matches!(
                        record.operation(),
                        Some(OperationRecord::Root {
                            generation,
                            accepting_children: true,
                            ..
                        }) if generation == token.generation
                    )
            });
        valid
            .then_some(())
            .ok_or_else(|| self.invalid_operation_failure(state, class))
    }

    fn operation_record_for_claim(
        &self,
        state: &mut super::accounting::AccountingState,
        operation: Option<OperationToken>,
        principal: Option<positron_domain::identity::PrincipalId>,
        class: super::WorkClass,
    ) -> Result<Option<OperationRecord>, AdmissionFailure> {
        if let Some(token) = operation {
            return Ok(Some(OperationRecord::Child {
                root_slot: token.root_slot,
                generation: token.generation,
            }));
        }
        if principal.is_none() {
            return Ok(None);
        }
        let generation = state.next_operation_generation;
        let Some(next) = generation.checked_add(1) else {
            state.lifecycle = GovernorLifecycle::Fenced;
            return Err(internal_failure_at_pressure(class, state.disk_pressure));
        };
        state.next_operation_generation = next;
        Ok(Some(OperationRecord::Root {
            generation,
            accepting_children: true,
            child_count: 0,
        }))
    }

    fn operation_usage(
        &self,
        state: &super::accounting::AccountingState,
        token: OperationToken,
        excluded_slot: Option<u16>,
        class: super::WorkClass,
    ) -> Result<super::ResourceAmounts, AdmissionFailure> {
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
            let belongs = matches!(
                record.operation(),
                Some(OperationRecord::Root { generation, .. })
                    if slot == token.root_slot && generation == token.generation
            ) || matches!(
                record.operation(),
                Some(OperationRecord::Child { root_slot, generation })
                    if root_slot == token.root_slot && generation == token.generation
            );
            if belongs {
                usage = usage
                    .checked_add(record.amounts())
                    .ok_or_else(|| internal_failure_at_pressure(class, state.disk_pressure))?;
            }
        }
        Ok(usage)
    }

    fn invalid_operation_failure(
        &self,
        state: &super::accounting::AccountingState,
        class: super::WorkClass,
    ) -> AdmissionFailure {
        failure_at_pressure(
            AdmissionFailureCode::PrincipalQuotaExceeded,
            AdmissionRetry::AfterCapacityRelease,
            LimitingScope::Operation,
            class,
            state.disk_pressure,
            DecisionLimit {
                dimension: None,
                allowed: 0,
                in_use: 0,
                requested: 1,
            },
        )
    }
}
