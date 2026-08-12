//! Fixed-cardinality ordinary and recovery fairness derivation.

use super::claim::WorkClass;
use super::failure::GovernorFailure;
use super::inventory::TenantQuota;
use super::model::{ResourceAmounts, ResourceDimension};
use super::policy::{OrdinaryPool, PoolCapacities, weighted_floor};
use super::recovery_policy::RecoveryPoolCapacities;
use super::{RecoveryWorkKind, lifecycle};

pub(super) fn total_weight(quotas: &[TenantQuota]) -> Result<u64, GovernorFailure> {
    quotas
        .iter()
        .try_fold(0_u64, |total, quota| {
            total.checked_add(u64::from(quota.weight))
        })
        .filter(|weight| *weight > 0)
        .ok_or(GovernorFailure::InvalidConfiguration)
}

pub(super) fn ordinary_capacities(
    quotas: &[TenantQuota],
    pools: PoolCapacities,
    total_weight: u64,
    mut capacities: Vec<PoolCapacities>,
) -> Result<Vec<PoolCapacities>, GovernorFailure> {
    for quota in quotas {
        capacities.push(
            pools
                .fair_share(quota.weight, total_weight)
                .ok_or(GovernorFailure::InvalidConfiguration)?,
        );
    }
    Ok(capacities)
}

pub(super) fn amount_capacities(
    quotas: &[TenantQuota],
    total: ResourceAmounts,
    total_weight: u64,
    mut capacities: Vec<ResourceAmounts>,
) -> Result<Vec<ResourceAmounts>, GovernorFailure> {
    for quota in quotas {
        capacities.push(
            weighted_amounts(total, quota.weight, total_weight)
                .ok_or(GovernorFailure::InvalidConfiguration)?,
        );
    }
    Ok(capacities)
}

pub(super) fn recovery_pool_capacities(
    quotas: &[TenantQuota],
    pools: RecoveryPoolCapacities,
    total_weight: u64,
    mut capacities: Vec<RecoveryPoolCapacities>,
) -> Result<Vec<RecoveryPoolCapacities>, GovernorFailure> {
    for quota in quotas {
        let mut values = [ResourceAmounts::zero(); 7];
        for kind in RecoveryWorkKind::ALL {
            let tenant_capacity = if kind.permits_tenant_scope() && kind.permits_system_scope() {
                pools
                    .get(kind)
                    .checked_sub(ResourceAmounts::new([1; 11]))
                    .ok_or(GovernorFailure::SystemRecoveryProgressUnavailable {
                        kind,
                        dimension: ResourceDimension::MemoryBytes,
                    })?
            } else if kind.permits_tenant_scope() {
                pools.get(kind)
            } else {
                ResourceAmounts::zero()
            };
            let share = weighted_amounts(tenant_capacity, quota.weight, total_weight)
                .ok_or(GovernorFailure::InvalidConfiguration)?;
            if kind.permits_tenant_scope() {
                for dimension in ResourceDimension::ALL {
                    if share.get(dimension) == 0 {
                        return Err(GovernorFailure::TenantProgressUnavailable {
                            tenant: quota.tenant,
                            class: WorkClass::DurabilityRecovery,
                            dimension,
                        });
                    }
                }
            }
            let slot = values
                .get_mut(kind.index())
                .ok_or(GovernorFailure::InvalidConfiguration)?;
            *slot = share;
        }
        capacities.push(RecoveryPoolCapacities::from_raw(values));
    }
    Ok(capacities)
}

pub(super) fn validate_system_recovery_progress(
    quotas: &[TenantQuota],
    pools: RecoveryPoolCapacities,
) -> Result<(), GovernorFailure> {
    let tenant_count =
        u64::try_from(quotas.len()).map_err(|_| GovernorFailure::InvalidConfiguration)?;
    for kind in RecoveryWorkKind::ALL {
        if !kind.permits_system_scope() {
            continue;
        }
        let required = if kind.permits_tenant_scope() {
            tenant_count
                .checked_add(1)
                .ok_or(GovernorFailure::InvalidConfiguration)?
        } else {
            1
        };
        for dimension in ResourceDimension::ALL {
            if pools.get(kind).get(dimension) < required {
                return Err(GovernorFailure::SystemRecoveryProgressUnavailable { kind, dimension });
            }
        }
    }
    Ok(())
}

pub(super) fn system_recovery_capacities(
    pools: RecoveryPoolCapacities,
    tenant_floors: &[RecoveryPoolCapacities],
) -> Result<RecoveryPoolCapacities, GovernorFailure> {
    let mut values = [ResourceAmounts::zero(); 7];
    for kind in RecoveryWorkKind::ALL {
        let mut reserved = ResourceAmounts::zero();
        if kind.permits_system_scope() && kind.permits_tenant_scope() {
            for floors in tenant_floors {
                reserved = reserved
                    .checked_add(floors.get(kind))
                    .ok_or(GovernorFailure::InvalidConfiguration)?;
            }
        }
        let slot = values
            .get_mut(kind.index())
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        *slot = pools
            .get(kind)
            .checked_sub(reserved)
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        if kind.permits_system_scope() {
            for dimension in ResourceDimension::ALL {
                if slot.get(dimension) == 0 {
                    return Err(GovernorFailure::SystemRecoveryProgressUnavailable {
                        kind,
                        dimension,
                    });
                }
            }
        }
    }
    Ok(RecoveryPoolCapacities::from_raw(values))
}

fn weighted_amounts(
    total: ResourceAmounts,
    weight: u16,
    total_weight: u64,
) -> Option<ResourceAmounts> {
    let mut share = ResourceAmounts::zero();
    for dimension in ResourceDimension::ALL {
        share = share.with_amount(
            dimension,
            weighted_floor(total.get(dimension), weight, total_weight)?,
        );
    }
    Some(share)
}

pub(super) fn validate_progress(
    quotas: &[TenantQuota],
    fair: &[PoolCapacities],
    maximum_outstanding: u32,
) -> Result<(), GovernorFailure> {
    let tenant_count =
        u32::try_from(quotas.len()).map_err(|_| GovernorFailure::InvalidConfiguration)?;
    let required = tenant_count
        .checked_add(lifecycle::WORK_CLASS_COUNT)
        .ok_or(GovernorFailure::InvalidConfiguration)?;
    if maximum_outstanding < required {
        return Err(GovernorFailure::InsufficientOutstandingProgress {
            configured: maximum_outstanding,
            required,
        });
    }
    for (index, quota) in quotas.iter().enumerate() {
        let pool_share = fair
            .get(index)
            .copied()
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        for class in [
            WorkClass::SecurityLifecycle,
            WorkClass::Ingest,
            WorkClass::InteractiveQueryTail,
            WorkClass::OrdinaryMaintenanceBackup,
        ] {
            let class_pool =
                OrdinaryPool::for_class(class).ok_or(GovernorFailure::InvalidConfiguration)?;
            for dimension in ResourceDimension::ALL {
                let accessible = pool_share
                    .get(OrdinaryPool::Shared)
                    .get(dimension)
                    .checked_add(pool_share.get(class_pool).get(dimension))
                    .ok_or(GovernorFailure::InvalidConfiguration)?;
                if accessible == 0 {
                    return Err(GovernorFailure::TenantProgressUnavailable {
                        tenant: quota.tenant,
                        class,
                        dimension,
                    });
                }
            }
        }
    }
    Ok(())
}
