use std::panic::{AssertUnwindSafe, catch_unwind};

use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionCompletionState, AdmissionFailureCode, AdmissionRetry, DetectedCapacity,
    DiskObservation, DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits,
    LimitingScope, OperatorLimits, OrdinaryPool, OrdinaryPoolPolicy, RecoveryReserve,
    RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension, ResourceInventory,
    TenantQuota, WorkClaim, WorkKind,
};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn establish<const N: usize>(
    tenants: [TenantQuota; N],
    maximum_outstanding: u32,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
    let reserve = resource_governor_support::minimum_recovery_reserve_for_tenants(N)?;
    let total = 90_u64.checked_add(reserve).ok_or("test total overflow")?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                maximum_outstanding,
                N,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                maximum_outstanding,
                N,
            )?,
        )?,
        RecoveryReserve::new(uniform(reserve))?,
        InventoryCardinalityLimits::new(N, maximum_outstanding)?,
        DiskPressureThresholds::new(reserve, reserve + 1, reserve + 2, reserve + 3)?,
        DiskObservation::new(total),
    )?;
    let policy = GovernorPolicy::new(
        tenants,
        OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))?,
    )?;
    TestKernel::establish_with_recovery_pools(
        inventory,
        policy,
        resource_governor_support::recovery_pools_for_tenants(N)?,
    )
}

fn memory_claim(
    tenant: TenantId,
    kind: WorkKind,
    amount: u64,
) -> Result<WorkClaim, Box<dyn std::error::Error>> {
    Ok(WorkClaim::tenant(
        tenant,
        kind,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, amount)?,
    )?)
}

#[test]
fn retry_storm_returns_stable_evidence_without_retaining_charges()
-> Result<(), Box<dyn std::error::Error>> {
    const RETRIES: u64 = 512;
    let primary = tenant(81)?;
    let governor = establish([TenantQuota::new(primary, 1, uniform(90))?], 600)?;
    let saturated = governor.reserve(memory_claim(primary, WorkKind::InteractiveQueryTail, 50)?)?;
    assert_eq!(
        format!("{saturated:?}"),
        "ResourceReservation { <bounded capability> }"
    );

    let mut first_failure = None;
    for _ in 0..RETRIES {
        let failure = governor
            .reserve(memory_claim(primary, WorkKind::InteractiveQueryTail, 1)?)
            .expect_err("query class headroom is saturated");
        assert_eq!(
            failure.code(),
            AdmissionFailureCode::ClassCapacityUnavailable
        );
        assert_eq!(failure.retry(), AdmissionRetry::AfterCapacityRelease);
        assert_eq!(failure.to_string(), "resource admission refused");
        assert_eq!(failure.limiting_scope(), LimitingScope::ClassHeadroom);
        assert_eq!(
            failure.completion_state(),
            AdmissionCompletionState::RejectedBeforeReservation
        );
        if let Some(expected) = first_failure {
            assert_eq!(failure, expected);
        } else {
            first_failure = Some(failure);
        }
    }

    let during = governor.inspect()?;
    assert_eq!(during.outstanding_total(), 1);
    assert_eq!(during.usage(ResourceDimension::MemoryBytes), 50);
    assert_eq!(during.rejection_count(), RETRIES);
    drop(saturated);
    let drained = governor.inspect()?;
    assert_eq!(drained.outstanding_total(), 0);
    assert_eq!(drained.usage(ResourceDimension::MemoryBytes), 0);
    for pool in [
        OrdinaryPool::Shared,
        OrdinaryPool::SecurityLifecycle,
        OrdinaryPool::Ingest,
        OrdinaryPool::InteractiveQueryTail,
        OrdinaryPool::OrdinaryMaintenanceBackup,
    ] {
        assert_eq!(drained.pool_usage(pool, ResourceDimension::MemoryBytes), 0);
    }
    Ok(())
}

#[test]
fn panic_unwind_releases_raii_capacity_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let primary = tenant(82)?;
    let governor = establish([TenantQuota::new(primary, 1, uniform(90))?], 6)?;

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _grant = governor
            .reserve(
                memory_claim(primary, WorkKind::SecurityLifecycle, 60)
                    .expect("test claim must be valid"),
            )
            .expect("capacity must be available");
        panic!("intentional reservation-owner unwind");
    }));
    assert!(outcome.is_err());
    let after_unwind = governor.inspect()?;
    assert_eq!(after_unwind.outstanding_total(), 0);
    assert_eq!(after_unwind.usage(ResourceDimension::MemoryBytes), 0);

    let replacement = governor.reserve(memory_claim(primary, WorkKind::SecurityLifecycle, 60)?)?;
    drop(replacement);
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn outstanding_limit_preserves_one_slot_for_each_absent_work_class()
-> Result<(), Box<dyn std::error::Error>> {
    let primary = tenant(83)?;
    let governor = establish([TenantQuota::new(primary, 1, uniform(90))?], 6)?;
    let claim = memory_claim(primary, WorkKind::SecurityLifecycle, 1)?;
    let first = governor.reserve(claim)?;
    let second = governor.reserve(claim)?;

    let failure = governor
        .reserve(claim)
        .expect_err("four absent work classes retain four progress slots additively");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::OutstandingReservationLimit
    );
    assert_eq!(failure.allowed(), 6);
    assert_eq!(failure.in_use(), 2);
    assert_eq!(failure.requested(), 1);
    assert_eq!(governor.inspect()?.outstanding_total(), 2);

    drop((first, second));
    let replacement = governor.reserve(claim)?;
    assert_eq!(governor.inspect()?.outstanding_total(), 1);
    drop(replacement);
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn one_tenant_and_all_classes_progress_after_the_system_lane_opens()
-> Result<(), Box<dyn std::error::Error>> {
    let primary = tenant(92)?;
    let kernel = establish([TenantQuota::new(primary, 1, uniform(90))?], 6)?;
    let system = kernel.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let grants = [
        kernel.reserve(memory_claim(primary, WorkKind::SecurityLifecycle, 1)?)?,
        kernel.reserve(memory_claim(primary, WorkKind::SecurityLifecycle, 1)?)?,
        kernel.reserve(memory_claim(primary, WorkKind::Ingest, 1)?)?,
        kernel.reserve(memory_claim(primary, WorkKind::InteractiveQueryTail, 1)?)?,
        kernel.reserve(memory_claim(
            primary,
            WorkKind::OrdinaryMaintenanceBackup,
            1,
        )?)?,
    ];
    assert_eq!(kernel.inspect()?.outstanding_total(), 6);
    drop((system, grants));
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);

    let replacement = kernel.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop(replacement);
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn mixed_tenants_and_classes_saturate_only_their_exact_fair_partitions()
-> Result<(), Box<dyn std::error::Error>> {
    let first_tenant = tenant(84)?;
    let second_tenant = tenant(85)?;
    let governor = establish(
        [
            TenantQuota::new(first_tenant, 1, uniform(90))?,
            TenantQuota::new(second_tenant, 1, uniform(90))?,
        ],
        16,
    )?;

    let first_query = governor.reserve(memory_claim(
        first_tenant,
        WorkKind::InteractiveQueryTail,
        25,
    )?)?;
    let second_ingest = governor.reserve(memory_claim(second_tenant, WorkKind::Ingest, 27)?)?;
    let first_security =
        governor.reserve(memory_claim(first_tenant, WorkKind::SecurityLifecycle, 10)?)?;
    let second_maintenance = governor.reserve(memory_claim(
        second_tenant,
        WorkKind::OrdinaryMaintenanceBackup,
        2,
    )?)?;

    for (tenant, kind) in [
        (first_tenant, WorkKind::InteractiveQueryTail),
        (second_tenant, WorkKind::Ingest),
        (first_tenant, WorkKind::SecurityLifecycle),
        (second_tenant, WorkKind::OrdinaryMaintenanceBackup),
    ] {
        let failure = governor
            .reserve(memory_claim(tenant, kind, 1)?)
            .expect_err("each tenant/class partition is exactly saturated");
        assert!(matches!(
            failure.code(),
            AdmissionFailureCode::TenantFairShareExceeded
                | AdmissionFailureCode::ClassCapacityUnavailable
        ));
    }
    let snapshot = governor.inspect()?;
    assert_eq!(snapshot.outstanding_total(), 4);
    assert_eq!(
        snapshot.outstanding_for(positron_kernel::WorkClass::DurabilityRecovery),
        0
    );
    assert_eq!(
        snapshot.outstanding_for(positron_kernel::WorkClass::SecurityLifecycle),
        1
    );
    assert_eq!(
        snapshot.outstanding_for(positron_kernel::WorkClass::Ingest),
        1
    );
    assert_eq!(
        snapshot.outstanding_for(positron_kernel::WorkClass::InteractiveQueryTail),
        1
    );
    assert_eq!(
        snapshot.outstanding_for(positron_kernel::WorkClass::OrdinaryMaintenanceBackup),
        1
    );
    assert_eq!(snapshot.usage(ResourceDimension::MemoryBytes), 64);
    assert_eq!(
        snapshot.pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        40
    );
    drop((
        second_maintenance,
        first_security,
        second_ingest,
        first_query,
    ));
    assert_eq!(governor.inspect()?.usage(ResourceDimension::MemoryBytes), 0);
    Ok(())
}

#[test]
fn maintenance_keeps_protected_progress_after_higher_classes_saturate_their_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let primary = tenant(86)?;
    let governor = establish([TenantQuota::new(primary, 1, uniform(90))?], 8)?;
    let security = governor.reserve(memory_claim(primary, WorkKind::SecurityLifecycle, 60)?)?;
    let ingest = governor.reserve(memory_claim(primary, WorkKind::Ingest, 15)?)?;
    let query = governor.reserve(memory_claim(primary, WorkKind::InteractiveQueryTail, 10)?)?;

    let maintenance = governor.reserve(memory_claim(
        primary,
        WorkKind::OrdinaryMaintenanceBackup,
        5,
    )?)?;
    let snapshot = governor.inspect()?;
    assert_eq!(snapshot.usage(ResourceDimension::MemoryBytes), 90);
    assert_eq!(
        snapshot.pool_usage(
            OrdinaryPool::OrdinaryMaintenanceBackup,
            ResourceDimension::MemoryBytes,
        ),
        5
    );
    drop((security, ingest, query, maintenance));
    assert_eq!(governor.inspect()?.usage(ResourceDimension::MemoryBytes), 0);
    Ok(())
}

#[test]
fn five_tenants_and_all_classes_progress_after_the_system_lane_opens()
-> Result<(), Box<dyn std::error::Error>> {
    let tenants = [
        tenant(87)?,
        tenant(88)?,
        tenant(89)?,
        tenant(90)?,
        tenant(91)?,
    ];
    let quotas = tenants
        .map(|tenant| TenantQuota::new(tenant, 1, uniform(90)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let quotas: [TenantQuota; 5] = quotas.try_into().map_err(|_| "exact tenant count")?;
    let below = establish(quotas, 9);
    assert!(matches!(
        below,
        Err(error)
            if error.downcast_ref::<positron_kernel::GovernorFailure>().is_some_and(|failure| {
                *failure == positron_kernel::GovernorFailure::InsufficientOutstandingProgress {
                    configured: 9,
                    required: 10,
                }
            })
    ));

    let quotas = tenants
        .map(|tenant| TenantQuota::new(tenant, 1, uniform(90)))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let quotas: [TenantQuota; 5] = quotas.try_into().map_err(|_| "exact tenant count")?;
    let kernel = establish(quotas, 10)?;
    let system = kernel.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let grants = [
        kernel.reserve(memory_claim(tenants[0], WorkKind::SecurityLifecycle, 1)?)?,
        kernel.reserve(memory_claim(tenants[1], WorkKind::Ingest, 1)?)?,
        kernel.reserve(memory_claim(tenants[2], WorkKind::InteractiveQueryTail, 1)?)?,
        kernel.reserve(memory_claim(
            tenants[3],
            WorkKind::OrdinaryMaintenanceBackup,
            1,
        )?)?,
        kernel.reserve(memory_claim(tenants[4], WorkKind::SecurityLifecycle, 1)?)?,
        kernel.reserve(memory_claim(tenants[0], WorkKind::SecurityLifecycle, 1)?)?,
        kernel.reserve(memory_claim(tenants[0], WorkKind::Ingest, 1)?)?,
        kernel.reserve(memory_claim(tenants[0], WorkKind::InteractiveQueryTail, 1)?)?,
        kernel.reserve(memory_claim(
            tenants[0],
            WorkKind::OrdinaryMaintenanceBackup,
            1,
        )?)?,
    ];
    assert_eq!(kernel.inspect()?.outstanding_total(), 10);
    drop((system, grants));
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);

    let replacement = kernel.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop(replacement);
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
