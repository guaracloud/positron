use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionCompletionState, AdmissionFailure, AdmissionFailureCode, AdmissionRetry,
    DetectedCapacity, DiskObservation, DiskPressureThresholds, ExistingCapacityDisposition,
    GovernorLifecycle, GovernorPolicy, InventoryCardinalityLimits, LimitingScope, OperatorLimits,
    OrdinaryPoolPolicy, RecoveryPoolCapacities, RecoveryReserve, RecoveryWorkClaim,
    RecoveryWorkKind, ResizeFailure, ResourceAmounts, ResourceDimension, ResourceInventory,
    TenantQuota, WorkClaim, WorkClass, WorkKind,
};

fn uniform(amount: u64) -> ResourceAmounts {
    ResourceAmounts::new([amount; 11])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn establish(first: TenantId, second: TenantId) -> Result<TestKernel, Box<dyn std::error::Error>> {
    const RESERVE: u64 = 24;
    const TOTAL: u64 = 114;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(TOTAL),
                16,
                2,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(TOTAL),
                16,
                2,
            )?,
        )?,
        RecoveryReserve::new(uniform(RESERVE))?,
        InventoryCardinalityLimits::new(2, 16)?,
        DiskPressureThresholds::new(RESERVE, RESERVE + 1, RESERVE + 2, RESERVE + 3)?,
        DiskObservation::new(TOTAL),
    )?;
    TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new(
            [
                TenantQuota::new(first, 1, uniform(90))?,
                TenantQuota::new(second, 1, uniform(90))?,
            ],
            OrdinaryPoolPolicy::new(uniform(3), uniform(2), uniform(1), uniform(1))?,
        )?,
        RecoveryPoolCapacities::new(
            uniform(3),
            uniform(2),
            uniform(3),
            uniform(2),
            uniform(10),
            uniform(2),
            uniform(2),
        )?,
    )
}

fn repair(
    tenant: TenantId,
    dimension: ResourceDimension,
    amount: u64,
) -> Result<RecoveryWorkClaim, Box<dyn std::error::Error>> {
    Ok(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(dimension, amount)?,
    )?)
}

fn retention(
    tenant: TenantId,
    dimension: ResourceDimension,
    amount: u64,
) -> Result<RecoveryWorkClaim, Box<dyn std::error::Error>> {
    Ok(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::only(dimension, amount)?,
    )?)
}

fn assert_exceeds(allowed: u64, in_use: u64, requested: u64) {
    let candidate = in_use
        .checked_add(requested)
        .expect("bounded test evidence does not overflow");
    assert!(
        candidate > allowed,
        "failure evidence must prove the refusal"
    );
}

fn assert_scope_failure(failure: AdmissionFailure, dimension: ResourceDimension) {
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::TenantFairShareExceeded
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::TenantFairShare);
    assert_eq!(failure.limiting_dimension(), Some(dimension));
    assert_exceeds(failure.allowed(), failure.in_use(), failure.requested());
}

fn assert_scope_resize(failure: ResizeFailure, dimension: ResourceDimension) {
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::TenantFairShareExceeded)
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::TenantFairShare);
    assert_eq!(failure.limiting_dimension(), Some(dimension));
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert_exceeds(failure.allowed(), failure.in_use(), failure.requested());
}

fn assert_global_failure(failure: AdmissionFailure, dimension: ResourceDimension) {
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::RecoveryReserveExhausted
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::RecoveryReserve);
    assert_eq!(failure.limiting_dimension(), Some(dimension));
    assert_exceeds(failure.allowed(), failure.in_use(), failure.requested());
}

fn assert_global_resize(failure: ResizeFailure, dimension: ResourceDimension) {
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::RecoveryReserveExhausted)
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::RecoveryReserve);
    assert_eq!(failure.limiting_dimension(), Some(dimension));
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert_exceeds(failure.allowed(), failure.in_use(), failure.requested());
}

#[test]
fn planner_distinguishes_scope_from_global_exhaustion_for_every_dimension()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(61)?;
    let second = tenant(62)?;
    for dimension in ResourceDimension::ALL {
        let scope_kernel = establish(first, second)?;
        let mut scope_grant = scope_kernel
            .recovery()
            .reserve(repair(first, dimension, 49)?)?;
        let scope_resize = scope_grant
            .try_resize(ResourceAmounts::only(dimension, 50)?)
            .expect_err("the replacement fits globally but exceeds one tenant scope");
        assert_scope_resize(scope_resize, dimension);
        let scope_grant = scope_kernel
            .recovery()
            .reserve(repair(first, dimension, 49)?)?;
        let scope_admission = scope_kernel
            .recovery()
            .reserve(repair(first, dimension, 1)?)
            .expect_err("the additional claim fits globally but exceeds one tenant scope");
        assert_scope_failure(scope_admission, dimension);
        drop(scope_grant);

        let global_kernel = establish(first, second)?;
        let first_full = global_kernel
            .recovery()
            .reserve(repair(first, dimension, 49)?)?;
        let second_full = global_kernel
            .recovery()
            .reserve(repair(second, dimension, 49)?)?;
        let global_admission = global_kernel
            .recovery()
            .reserve(RecoveryWorkClaim::system(
                RecoveryWorkKind::Repair,
                ResourceAmounts::only(dimension, 3)?,
            )?)
            .expect_err("the system scope fits while the global recovery pool is exhausted");
        assert_global_failure(global_admission, dimension);
        drop((first_full, second_full));

        let mut system = global_kernel.recovery().reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::Repair,
            ResourceAmounts::only(dimension, 1)?,
        )?)?;
        let first_full = global_kernel
            .recovery()
            .reserve(repair(first, dimension, 49)?)?;
        let second_near_full = global_kernel
            .recovery()
            .reserve(repair(second, dimension, 48)?)?;
        let global_resize = system
            .try_resize(ResourceAmounts::only(dimension, 4)?)
            .expect_err("the replacement fits its system scope but not the global pool");
        assert_global_resize(global_resize, dimension);
        drop((first_full, second_near_full));
        assert_eq!(global_kernel.inspect()?.outstanding_total(), 0);
    }
    Ok(())
}

#[test]
fn ordinary_admission_counts_tenant_recovery_shared_occupancy_for_every_dimension()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(63)?;
    let second = tenant(64)?;
    for dimension in ResourceDimension::ALL {
        let kernel = establish(first, second)?;
        let first_recovery = kernel
            .recovery()
            .reserve(retention(second, dimension, 14)?)?;
        let second_recovery = kernel
            .recovery()
            .reserve(retention(second, dimension, 17)?)?;
        let before = kernel.inspect()?;
        assert_eq!(before.usage(dimension), 31);
        assert_eq!(before.recovery_shared_usage(dimension), 31);
        assert_eq!(before.outstanding_total(), 2);

        let failure = kernel
            .reserve(WorkClaim::tenant(
                second,
                WorkKind::Ingest,
                ResourceAmounts::only(dimension, 15)?,
            )?)
            .expect_err("ordinary work cannot overfill its tenant recovery Shared fair share");
        assert_eq!(
            failure.code(),
            AdmissionFailureCode::TenantFairShareExceeded
        );
        assert_eq!(failure.retry(), AdmissionRetry::AfterCapacityRelease);
        assert_eq!(failure.limiting_scope(), LimitingScope::TenantFairShare);
        assert_eq!(failure.work_class(), WorkClass::Ingest);
        assert_eq!(
            failure.completion_state(),
            AdmissionCompletionState::RejectedBeforeReservation
        );
        assert_eq!(failure.limiting_dimension(), Some(dimension));
        assert_eq!(failure.allowed(), 45);
        assert_eq!(failure.in_use(), 31);
        assert_eq!(failure.requested(), 15);

        let refused = kernel.inspect()?;
        assert_eq!(refused.lifecycle(), GovernorLifecycle::Open);
        assert_eq!(refused.usage(dimension), 31);
        assert_eq!(refused.recovery_shared_usage(dimension), 31);
        assert_eq!(refused.outstanding_total(), 2);
        assert_eq!(
            refused.rejection_count_for(AdmissionFailureCode::TenantFairShareExceeded),
            1
        );
        assert_eq!(
            refused.throttle_count_for(AdmissionFailureCode::TenantFairShareExceeded),
            1
        );

        drop((first_recovery, second_recovery));
        let reconciled = kernel.inspect()?;
        assert!(reconciled.complete());
        assert_eq!(reconciled.usage(dimension), 0);
        assert_eq!(reconciled.recovery_shared_usage(dimension), 0);

        let valid = kernel.reserve(WorkClaim::tenant(
            second,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 15)?,
        )?)?;
        assert_eq!(valid.granted().get(dimension), 15);
        drop(valid);
        assert!(kernel.inspect()?.complete());
    }
    Ok(())
}

#[test]
fn ordinary_resize_counts_existing_ordinary_and_recovery_shared_usage_for_every_dimension()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(65)?;
    let second = tenant(66)?;
    for dimension in ResourceDimension::ALL {
        let kernel = establish(first, second)?;
        let existing = kernel.reserve(WorkClaim::tenant(
            second,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 5)?,
        )?)?;
        let mut replacement = kernel.reserve(WorkClaim::tenant(
            second,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 1)?,
        )?)?;
        let first_recovery = kernel
            .recovery()
            .reserve(retention(second, dimension, 14)?)?;
        let second_recovery = kernel
            .recovery()
            .reserve(retention(second, dimension, 17)?)?;

        let failure = replacement
            .try_resize(ResourceAmounts::only(dimension, 10)?)
            .expect_err("replacement cannot overfill its tenant recovery Shared fair share");
        assert_scope_resize(failure, dimension);
        assert_eq!(failure.allowed(), 45);
        assert_eq!(failure.in_use(), 36);
        assert_eq!(failure.requested(), 10);
        assert_eq!(failure.work_class(), WorkClass::Ingest);
        assert!(!replacement.is_active());

        let refused = kernel.inspect()?;
        assert_eq!(refused.lifecycle(), GovernorLifecycle::Open);
        assert_eq!(refused.usage(dimension), 36);
        assert_eq!(refused.recovery_shared_usage(dimension), 31);
        assert_eq!(refused.outstanding_total(), 3);
        assert_eq!(refused.outstanding_ordinary(), 1);
        assert_eq!(refused.outstanding_recovery(), 2);
        assert_eq!(
            refused.rejection_count_for(AdmissionFailureCode::TenantFairShareExceeded),
            1
        );
        assert_eq!(
            refused.throttle_count_for(AdmissionFailureCode::TenantFairShareExceeded),
            1
        );

        drop((first_recovery, second_recovery));
        assert_eq!(kernel.inspect()?.usage(dimension), 5);
        let valid = kernel.reserve(WorkClaim::tenant(
            second,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 10)?,
        )?)?;
        assert_eq!(kernel.inspect()?.usage(dimension), 15);
        drop((existing, valid));
        assert!(kernel.inspect()?.complete());
    }
    Ok(())
}

#[test]
fn recovery_admission_already_preserves_combined_tenant_shared_fairness_for_every_dimension()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(67)?;
    let second = tenant(68)?;
    for dimension in ResourceDimension::ALL {
        let kernel = establish(first, second)?;
        let mut ordinary = kernel.reserve(WorkClaim::tenant(
            second,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 15)?,
        )?)?;
        let first_recovery = kernel
            .recovery()
            .reserve(retention(second, dimension, 14)?)?;
        let second_recovery = kernel
            .recovery()
            .reserve(retention(second, dimension, 17)?)?;

        let occupied = kernel.inspect()?;
        assert_eq!(occupied.usage(dimension), 46);
        assert_eq!(occupied.recovery_shared_usage(dimension), 30);
        assert_eq!(
            occupied.recovery_pool_usage(RecoveryWorkKind::Retention, dimension),
            1
        );
        let failure = kernel
            .recovery()
            .reserve(retention(second, dimension, 1)?)
            .expect_err("recovery cannot overfill ordinary plus tenant Shared occupancy");
        assert_scope_failure(failure, dimension);
        assert_eq!(failure.allowed(), 46);
        assert_eq!(failure.in_use(), 46);
        assert_eq!(failure.requested(), 1);
        assert_eq!(kernel.inspect()?.lifecycle(), GovernorLifecycle::Open);
        let shrink = ordinary.try_resize(ResourceAmounts::only(dimension, 14)?)?;
        assert_eq!(shrink.released().get(dimension), 1);
        assert_eq!(shrink.added().get(dimension), 0);
        assert_eq!(ordinary.granted().get(dimension), 14);
        assert_eq!(kernel.inspect()?.usage(dimension), 45);

        let beside_protected = kernel.reserve(WorkClaim::tenant(
            second,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 1)?,
        )?)?;
        let shared_only_overlap = kernel.inspect()?;
        assert_eq!(shared_only_overlap.usage(dimension), 46);
        assert_eq!(shared_only_overlap.recovery_shared_usage(dimension), 30);
        assert_eq!(
            shared_only_overlap.recovery_pool_usage(RecoveryWorkKind::Retention, dimension),
            1
        );

        drop((ordinary, beside_protected, first_recovery, second_recovery));
        let reconciled = kernel.inspect()?;
        assert!(reconciled.complete());
        assert_eq!(reconciled.usage(dimension), 0);
        assert_eq!(reconciled.recovery_shared_usage(dimension), 0);
        assert_eq!(
            reconciled.recovery_pool_usage(RecoveryWorkKind::Retention, dimension),
            0
        );
    }
    Ok(())
}

use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
