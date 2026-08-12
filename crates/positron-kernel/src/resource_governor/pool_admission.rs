//! Ordinary pool allocation and pressure eligibility.

use super::claim::WorkClass;
use super::decision::{DecisionLimit, failure_at_pressure, internal_failure_at_pressure};
use super::failure::{
    AdmissionFailure, AdmissionFailureCode, AdmissionRetry, DiskPressureState, LimitingScope,
};
use super::model::{ResourceAmounts, ResourceDimension};
use super::policy::{OrdinaryPool, PoolCapacities, PoolCharge};

pub(super) struct PoolAdmission {
    pub(super) global_capacity: PoolCapacities,
    pub(super) global_usage: PoolCapacities,
    pub(super) tenant_capacity: PoolCapacities,
    pub(super) tenant_usage: PoolCapacities,
}

pub(super) fn plan_pool_charge(
    class: WorkClass,
    requested: ResourceAmounts,
    admission: PoolAdmission,
    pressure: DiskPressureState,
    shared_eligible: bool,
) -> Result<PoolCharge, AdmissionFailure> {
    let Some(class_pool) = OrdinaryPool::for_class(class) else {
        return Err(internal_failure_at_pressure(class, pressure));
    };
    let mut shared_charge = ResourceAmounts::zero();
    let mut class_charge = ResourceAmounts::zero();
    for dimension in ResourceDimension::ALL {
        let global_shared = available(
            admission.global_capacity,
            admission.global_usage,
            OrdinaryPool::Shared,
            dimension,
        )
        .ok_or_else(|| internal_failure_at_pressure(class, pressure))?;
        let tenant_shared = available(
            admission.tenant_capacity,
            admission.tenant_usage,
            OrdinaryPool::Shared,
            dimension,
        )
        .ok_or_else(|| internal_failure_at_pressure(class, pressure))?;
        let shared = if shared_eligible {
            requested
                .get(dimension)
                .min(global_shared)
                .min(tenant_shared)
        } else {
            0
        };
        let remainder = requested.get(dimension) - shared;
        let global_class = available(
            admission.global_capacity,
            admission.global_usage,
            class_pool,
            dimension,
        )
        .ok_or_else(|| internal_failure_at_pressure(class, pressure))?;
        if remainder > global_class {
            if !shared_eligible {
                return Err(pressure_failure(pressure, class, requested));
            }
            return Err(pool_failure(
                AdmissionFailureCode::ClassCapacityUnavailable,
                LimitingScope::ClassHeadroom,
                class,
                dimension,
                PoolLimit {
                    capacity: admission.global_capacity,
                    usage: admission.global_usage,
                    class_pool,
                },
                requested.get(dimension),
                pressure,
            ));
        }
        let tenant_class = available(
            admission.tenant_capacity,
            admission.tenant_usage,
            class_pool,
            dimension,
        )
        .ok_or_else(|| internal_failure_at_pressure(class, pressure))?;
        if remainder > tenant_class {
            if !shared_eligible {
                return Err(pressure_failure(pressure, class, requested));
            }
            return Err(pool_failure(
                AdmissionFailureCode::TenantFairShareExceeded,
                LimitingScope::TenantFairShare,
                class,
                dimension,
                PoolLimit {
                    capacity: admission.tenant_capacity,
                    usage: admission.tenant_usage,
                    class_pool,
                },
                requested.get(dimension),
                pressure,
            ));
        }
        shared_charge = shared_charge.with_amount(dimension, shared);
        class_charge = class_charge.with_amount(dimension, remainder);
    }
    Ok(PoolCharge::new(class_pool, shared_charge, class_charge))
}

pub(super) fn pressure_eligibility(
    pressure: DiskPressureState,
    class: WorkClass,
    amounts: ResourceAmounts,
) -> Result<bool, AdmissionFailure> {
    let disk_growth = amounts.get(ResourceDimension::DiskHeadroomBytes);
    match pressure {
        DiskPressureState::Healthy => Ok(true),
        DiskPressureState::SoftPressure => match class {
            WorkClass::SecurityLifecycle | WorkClass::Ingest => Ok(true),
            WorkClass::InteractiveQueryTail => Ok(false),
            WorkClass::OrdinaryMaintenanceBackup if disk_growth == 0 => Ok(false),
            WorkClass::OrdinaryMaintenanceBackup | WorkClass::DurabilityRecovery => {
                Err(pressure_failure(pressure, class, amounts))
            },
        },
        DiskPressureState::HardPressure => {
            if class == WorkClass::Ingest || disk_growth > 0 {
                return Err(pressure_failure(pressure, class, amounts));
            }
            match class {
                WorkClass::SecurityLifecycle => Ok(true),
                WorkClass::InteractiveQueryTail | WorkClass::OrdinaryMaintenanceBackup => Ok(false),
                WorkClass::Ingest | WorkClass::DurabilityRecovery => {
                    Err(pressure_failure(pressure, class, amounts))
                },
            }
        },
    }
}

pub(super) fn shutdown_failure(class: WorkClass, pressure: DiskPressureState) -> AdmissionFailure {
    failure_at_pressure(
        AdmissionFailureCode::ShuttingDown,
        AdmissionRetry::Never,
        LimitingScope::Policy,
        class,
        pressure,
        DecisionLimit::none(),
    )
}

fn pressure_failure(
    pressure: DiskPressureState,
    class: WorkClass,
    requested: ResourceAmounts,
) -> AdmissionFailure {
    failure_at_pressure(
        AdmissionFailureCode::DiskPressureAdmissionRefused,
        AdmissionRetry::AfterPressureTransition,
        LimitingScope::Policy,
        class,
        pressure,
        DecisionLimit {
            dimension: Some(ResourceDimension::DiskHeadroomBytes),
            allowed: 0,
            in_use: 0,
            requested: requested.get(ResourceDimension::DiskHeadroomBytes),
        },
    )
}

fn available(
    capacity: PoolCapacities,
    usage: PoolCapacities,
    pool: OrdinaryPool,
    dimension: ResourceDimension,
) -> Option<u64> {
    capacity
        .get(pool)
        .get(dimension)
        .checked_sub(usage.get(pool).get(dimension))
}

struct PoolLimit {
    capacity: PoolCapacities,
    usage: PoolCapacities,
    class_pool: OrdinaryPool,
}

fn pool_failure(
    code: AdmissionFailureCode,
    scope: LimitingScope,
    class: WorkClass,
    dimension: ResourceDimension,
    limit: PoolLimit,
    requested: u64,
    pressure: DiskPressureState,
) -> AdmissionFailure {
    let allowed = limit
        .capacity
        .get(OrdinaryPool::Shared)
        .get(dimension)
        .checked_add(limit.capacity.get(limit.class_pool).get(dimension));
    let in_use = limit
        .usage
        .get(OrdinaryPool::Shared)
        .get(dimension)
        .checked_add(limit.usage.get(limit.class_pool).get(dimension));
    let (Some(allowed), Some(in_use)) = (allowed, in_use) else {
        return internal_failure_at_pressure(class, pressure);
    };
    failure_at_pressure(
        code,
        AdmissionRetry::AfterCapacityRelease,
        scope,
        class,
        pressure,
        DecisionLimit {
            dimension: Some(dimension),
            allowed,
            in_use,
            requested,
        },
    )
}
