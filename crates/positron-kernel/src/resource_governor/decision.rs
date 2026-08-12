//! Stable refusal construction and multidimensional ceiling checks.

use super::claim::WorkClass;
use super::failure::{
    AdmissionEvidence, AdmissionFailure, AdmissionFailureCode, AdmissionRetry, DiskPressureState,
    LimitingScope,
};
use super::model::{ResourceAmounts, ResourceDimension};

pub(super) fn contention_failure(
    class: WorkClass,
    pressure: DiskPressureState,
) -> AdmissionFailure {
    failure_at_pressure(
        AdmissionFailureCode::GovernorContended,
        AdmissionRetry::AfterCapacityRelease,
        LimitingScope::Internal,
        class,
        pressure,
        DecisionLimit::none(),
    )
}

pub(super) struct DecisionLimit {
    pub(super) dimension: Option<ResourceDimension>,
    pub(super) allowed: u64,
    pub(super) in_use: u64,
    pub(super) requested: u64,
}

pub(super) struct OrdinaryCapacity {
    pub(super) ordinary_usage: ResourceAmounts,
    pub(super) recovery_shared_usage: ResourceAmounts,
    pub(super) ordinary_ceiling: ResourceAmounts,
    pub(super) total_ceiling: ResourceAmounts,
    pub(super) pressure: DiskPressureState,
}

impl DecisionLimit {
    pub(super) const fn none() -> Self {
        Self {
            dimension: None,
            allowed: 0,
            in_use: 0,
            requested: 0,
        }
    }
}

pub(super) fn refuse_exceeded(
    code: AdmissionFailureCode,
    scope: LimitingScope,
    class: WorkClass,
    in_use: ResourceAmounts,
    requested: ResourceAmounts,
    allowed: ResourceAmounts,
    pressure: DiskPressureState,
) -> Result<(), AdmissionFailure> {
    for dimension in ResourceDimension::ALL {
        let candidate = in_use.get(dimension).checked_add(requested.get(dimension));
        if candidate.is_none_or(|value| value > allowed.get(dimension)) {
            return Err(failure_at_pressure(
                code,
                AdmissionRetry::AfterCapacityRelease,
                scope,
                class,
                pressure,
                DecisionLimit {
                    dimension: Some(dimension),
                    allowed: allowed.get(dimension),
                    in_use: in_use.get(dimension),
                    requested: requested.get(dimension),
                },
            ));
        }
    }
    Ok(())
}

pub(super) fn refuse_tenant_recovery_shared_fair_share(
    class: WorkClass,
    ordinary_in_use: ResourceAmounts,
    recovery_shared_in_use: ResourceAmounts,
    requested: ResourceAmounts,
    allowed: ResourceAmounts,
    pressure: DiskPressureState,
) -> Result<(), AdmissionFailure> {
    let combined_in_use = ordinary_in_use
        .checked_add(recovery_shared_in_use)
        .ok_or_else(|| internal_failure_at_pressure(class, pressure))?;
    refuse_exceeded(
        AdmissionFailureCode::TenantFairShareExceeded,
        LimitingScope::TenantFairShare,
        class,
        combined_in_use,
        requested,
        allowed,
        pressure,
    )
}

pub(super) fn refuse_live_disk_growth(
    class: WorkClass,
    in_use: ResourceAmounts,
    requested: ResourceAmounts,
    usable_bytes: u64,
    pressure: DiskPressureState,
) -> Result<(), AdmissionFailure> {
    let dimension = ResourceDimension::DiskHeadroomBytes;
    let requested_bytes = requested.get(dimension);
    if requested_bytes == 0 {
        return Ok(());
    }
    let in_use_bytes = in_use.get(dimension);
    if in_use_bytes
        .checked_add(requested_bytes)
        .is_none_or(|candidate| candidate > usable_bytes)
    {
        return Err(failure_at_pressure(
            AdmissionFailureCode::CapacityExhausted,
            AdmissionRetry::AfterPressureTransition,
            LimitingScope::Global,
            class,
            pressure,
            DecisionLimit {
                dimension: Some(dimension),
                allowed: usable_bytes,
                in_use: in_use_bytes,
                requested: requested_bytes,
            },
        ));
    }
    Ok(())
}

pub(super) fn refuse_ordinary_capacity(
    class: WorkClass,
    requested: ResourceAmounts,
    capacity: OrdinaryCapacity,
) -> Result<(), AdmissionFailure> {
    for dimension in ResourceDimension::ALL {
        let ordinary_candidate = capacity
            .ordinary_usage
            .get(dimension)
            .checked_add(requested.get(dimension));
        if ordinary_candidate.is_none_or(|value| value > capacity.total_ceiling.get(dimension)) {
            return Err(capacity_failure(
                AdmissionFailureCode::CapacityExhausted,
                LimitingScope::Global,
                class,
                capacity.pressure,
                DecisionLimit {
                    dimension: Some(dimension),
                    allowed: capacity.total_ceiling.get(dimension),
                    in_use: capacity.ordinary_usage.get(dimension),
                    requested: requested.get(dimension),
                },
            ));
        }
        let shared_recovery = capacity.recovery_shared_usage.get(dimension);
        let Some(ordinary_available) = capacity
            .ordinary_ceiling
            .get(dimension)
            .checked_sub(shared_recovery)
        else {
            return Err(internal_failure_at_pressure(class, capacity.pressure));
        };
        if ordinary_candidate.is_none_or(|value| value > ordinary_available) {
            let recovery_occupied = shared_recovery > 0;
            return Err(capacity_failure(
                if recovery_occupied {
                    AdmissionFailureCode::CapacityOccupiedByRecovery
                } else {
                    AdmissionFailureCode::ProtectedCapacityUnavailable
                },
                if recovery_occupied {
                    LimitingScope::RecoveryOccupancy
                } else {
                    LimitingScope::ProtectedReserve
                },
                class,
                capacity.pressure,
                DecisionLimit {
                    dimension: Some(dimension),
                    allowed: ordinary_available,
                    in_use: capacity.ordinary_usage.get(dimension),
                    requested: requested.get(dimension),
                },
            ));
        }
    }
    Ok(())
}

pub(super) fn internal_failure(class: WorkClass) -> AdmissionFailure {
    failure(
        AdmissionFailureCode::InternalFenced,
        AdmissionRetry::Never,
        LimitingScope::Internal,
        class,
        DecisionLimit::none(),
    )
}

pub(super) fn internal_failure_at_pressure(
    class: WorkClass,
    pressure: DiskPressureState,
) -> AdmissionFailure {
    internal_failure(class).at_pressure(pressure)
}

pub(super) fn failure(
    code: AdmissionFailureCode,
    retry: AdmissionRetry,
    scope: LimitingScope,
    class: WorkClass,
    limit: DecisionLimit,
) -> AdmissionFailure {
    failure_at_pressure(code, retry, scope, class, DiskPressureState::Healthy, limit)
}

pub(super) fn failure_at_pressure(
    code: AdmissionFailureCode,
    retry: AdmissionRetry,
    scope: LimitingScope,
    class: WorkClass,
    pressure: DiskPressureState,
    limit: DecisionLimit,
) -> AdmissionFailure {
    AdmissionFailure::new(AdmissionEvidence {
        code,
        retry,
        scope,
        class,
        pressure,
        dimension: limit.dimension,
        allowed: limit.allowed,
        in_use: limit.in_use,
        requested: limit.requested,
    })
}

fn capacity_failure(
    code: AdmissionFailureCode,
    scope: LimitingScope,
    class: WorkClass,
    pressure: DiskPressureState,
    limit: DecisionLimit,
) -> AdmissionFailure {
    failure_at_pressure(
        code,
        AdmissionRetry::AfterCapacityRelease,
        scope,
        class,
        pressure,
        limit,
    )
}
