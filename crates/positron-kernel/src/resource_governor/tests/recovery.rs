use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionFailureCode, AdmissionRetry, DetectedCapacity, DiskObservation, DiskPressureState,
    DiskPressureThresholds, ExistingCapacityDisposition, GovernorFailure, GovernorPolicy,
    InventoryCardinalityLimits, LimitingScope, OperatorLimits, OrdinaryPoolPolicy,
    RecoveryInterruption, RecoveryPoolCapacities, RecoveryReserve, RecoveryScope,
    RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension, ResourceInventory,
    ResourceReservation, TenantQuota, WorkClaim, WorkKind,
};

fn uniform(amount: u64) -> ResourceAmounts {
    ResourceAmounts::new([amount; 11])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn pool_policy() -> Result<OrdinaryPoolPolicy, Box<dyn std::error::Error>> {
    Ok(OrdinaryPoolPolicy::new(
        uniform(3),
        uniform(2),
        uniform(1),
        uniform(1),
    )?)
}

fn disk_thresholds(reserve: u64) -> Result<DiskPressureThresholds, GovernorFailure> {
    DiskPressureThresholds::new(reserve, reserve + 1, reserve + 2, reserve + 3)
}

fn establish(
    tenant: TenantId,
    total: u64,
    reserve: u64,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
    let ordinary = total
        .checked_sub(reserve)
        .ok_or("reserve must fit total capacity")?;
    let configured_reserve =
        reserve.max(resource_governor_support::minimum_recovery_reserve_for_tenants(1)?);
    let configured_total = ordinary
        .checked_add(configured_reserve)
        .ok_or("configured test total overflow")?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(configured_total),
            8,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(configured_total),
            8,
        )?)?,
        RecoveryReserve::new(uniform(configured_reserve))?,
        InventoryCardinalityLimits::new(1, 8)?,
        disk_thresholds(configured_reserve)?,
        DiskObservation::new(configured_total),
    )?;
    TestKernel::establish(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, uniform(ordinary))?],
            pool_policy()?,
        )?,
    )
}

#[test]
fn batched_drop_of_mixed_ordinary_and_tenant_recovery_grants_reconciles()
-> Result<(), Box<dyn std::error::Error>> {
    let tenants = [tenant(81)?, tenant(82)?];
    let cardinality = InventoryCardinalityLimits::new(2, 8)?;
    let raw =
        resource_governor_support::raw_capacity_for_governed_work_for_tenants(uniform(105), 8, 2)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw)?,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(uniform(15))?,
        cardinality,
        DiskPressureThresholds::new(20, 30, 40, 50)?,
        DiskObservation::new(105),
    )?;
    let policy = GovernorPolicy::new(
        [
            TenantQuota::new(tenants[0], 1, uniform(90))?,
            TenantQuota::new(tenants[1], 1, uniform(90))?,
        ],
        OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))?,
    )?;
    let pools = RecoveryPoolCapacities::new(
        uniform(3),
        uniform(2),
        uniform(3),
        uniform(2),
        uniform(3),
        uniform(1),
        uniform(1),
    )?;
    let kernel = TestKernel::establish_with_recovery_pools(inventory, policy, pools)?;
    let recovery_a = kernel.recovery().reserve(RecoveryWorkClaim::tenant(
        tenants[1],
        RecoveryWorkKind::Retention,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 14)?,
    )?)?;
    let recovery_b = kernel.recovery().reserve(RecoveryWorkClaim::tenant(
        tenants[1],
        RecoveryWorkKind::Retention,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 17)?,
    )?)?;
    let ordinary = kernel.reserve(WorkClaim::tenant(
        tenants[0],
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 15)?,
    )?)?;

    assert!(!kernel.begin_shutdown()?.complete());
    drop((ordinary, recovery_b, recovery_a));
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);
    assert!(kernel.begin_shutdown()?.complete());
    Ok(())
}

#[test]
fn checkpointable_recovery_resize_cancellation_releases_all_accounting_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(83)?;
    let kernel = establish(tenant, 105, 15)?;
    let mut grant = kernel.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 17)?,
    )?)?;

    let failure = grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 91)?)
        .expect_err("tenant quota refuses the replacement and cancels retention");
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::TenantQuotaExceeded)
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::Tenant);
    assert_eq!(
        failure.limiting_dimension(),
        Some(ResourceDimension::MemoryBytes)
    );
    assert_eq!(failure.allowed(), 90);
    assert_eq!(failure.in_use(), 0);
    assert_eq!(failure.requested(), 91);
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert!(!grant.is_active());
    let cancelled = kernel.inspect()?;
    assert_eq!(cancelled.outstanding_total(), 0);
    assert_eq!(cancelled.outstanding_recovery(), 0);
    assert_eq!(cancelled.outstanding_uninterruptible(), 0);
    assert_eq!(cancelled.usage(ResourceDimension::MemoryBytes), 0);
    assert_eq!(
        cancelled.recovery_shared_usage(ResourceDimension::MemoryBytes),
        0
    );
    assert_eq!(
        cancelled.recovery_pool_usage(RecoveryWorkKind::Retention, ResourceDimension::MemoryBytes,),
        0
    );
    assert_eq!(
        cancelled.rejection_count_for(AdmissionFailureCode::TenantQuotaExceeded),
        1
    );

    let replacement = kernel.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 90)?,
    )?)?;
    let readmitted = kernel.inspect()?;
    assert_eq!(readmitted.outstanding_recovery(), 1);
    assert_eq!(readmitted.outstanding_uninterruptible(), 0);
    assert_eq!(readmitted.usage(ResourceDimension::MemoryBytes), 90);
    drop(replacement);
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);
    assert!(kernel.begin_shutdown()?.complete());
    Ok(())
}

fn fill_ordinary(
    governor: &TestKernel,
    tenant: TenantId,
) -> Result<[ResourceReservation<'_>; 4], Box<dyn std::error::Error>> {
    Ok([
        governor.reserve(WorkClaim::tenant(
            tenant,
            WorkKind::SecurityLifecycle,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 4)?,
        )?)?,
        governor.reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)?,
        governor.reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)?,
        governor.reserve(WorkClaim::tenant(
            tenant,
            WorkKind::OrdinaryMaintenanceBackup,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)?,
    ])
}

#[test]
fn ordinary_work_cannot_borrow_protected_recovery_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(21)?;
    let governor = establish(tenant, 10, 2)?;
    let ordinary = fill_ordinary(&governor, tenant)?;
    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("ordinary work must not consume protected capacity");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::ProtectedCapacityUnavailable
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::ProtectedReserve);
    assert_eq!(failure.allowed(), 8);
    assert_eq!(failure.in_use(), 8);
    assert_eq!(failure.requested(), 1);
    drop(ordinary);
    Ok(())
}

#[test]
fn full_ordinary_occupancy_preserves_every_system_recovery_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(51)?;
    for kind in [
        RecoveryWorkKind::DurabilityCompletion,
        RecoveryWorkKind::EmergencyCompaction,
        RecoveryWorkKind::Repair,
        RecoveryWorkKind::Fencing,
        RecoveryWorkKind::SafeShutdown,
    ] {
        let kernel = establish(tenant, 100, 10)?;
        let ordinary = [
            kernel.reserve(WorkClaim::tenant(
                tenant,
                WorkKind::SecurityLifecycle,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 86)?,
            )?)?,
            kernel.reserve(WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
            )?)?,
            kernel.reserve(WorkClaim::tenant(
                tenant,
                WorkKind::InteractiveQueryTail,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            )?)?,
            kernel.reserve(WorkClaim::tenant(
                tenant,
                WorkKind::OrdinaryMaintenanceBackup,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            )?)?,
        ];
        let system = kernel.recovery().reserve(RecoveryWorkClaim::system(
            kind,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)?;
        assert_eq!(
            kernel
                .inspect()?
                .recovery_pool_usage(kind, ResourceDimension::MemoryBytes),
            1
        );
        drop((system, ordinary));
        assert_eq!(kernel.inspect()?.outstanding_total(), 0);
    }
    Ok(())
}

#[test]
fn establishment_reports_the_exact_missing_system_recovery_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(52)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            6,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            6,
        )?)?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 6)?,
        disk_thresholds(10)?,
        DiskObservation::new(100),
    )?;
    let one = uniform(1);
    let result = positron_kernel::ResourceGovernorConfiguration::new(
        inventory,
        GovernorPolicy::new([TenantQuota::new(tenant, 1, uniform(90))?], pool_policy()?)?,
        RecoveryPoolCapacities::new(one, one, uniform(2), one, uniform(2), one, one)?,
    );
    assert!(matches!(
        result,
        Err(GovernorFailure::SystemRecoveryProgressUnavailable {
            kind: RecoveryWorkKind::DurabilityCompletion,
            dimension: ResourceDimension::MemoryBytes,
        })
    ));
    Ok(())
}

#[test]
fn recovery_consumes_unused_ordinary_then_reports_protected_use_and_releases()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(22)?;
    let kernel = establish(tenant, 10, 2)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let ordinary = fill_ordinary(governor, tenant)?;
    let system_protected = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let snapshot = governor.inspect()?;
    assert_eq!(
        snapshot.recovery_shared_capacity(ResourceDimension::MemoryBytes),
        8
    );
    assert_eq!(
        snapshot.recovery_shared_usage(ResourceDimension::MemoryBytes),
        0
    );
    assert_eq!(
        snapshot.recovery_pool_capacity(
            RecoveryWorkKind::SafeShutdown,
            ResourceDimension::MemoryBytes,
        ),
        1
    );
    assert_eq!(
        snapshot.recovery_pool_usage(
            RecoveryWorkKind::SafeShutdown,
            ResourceDimension::MemoryBytes,
        ),
        1
    );
    assert_eq!(
        snapshot.reserve_consumption(ResourceDimension::MemoryBytes),
        1
    );
    assert_eq!(snapshot.outstanding_reservations(), 5);
    drop(system_protected);
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        0
    );
    drop(ordinary);

    let recovery_in_ordinary_headroom = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 8)?,
    )?)?;
    assert_eq!(
        governor
            .inspect()?
            .reserve_consumption(ResourceDimension::MemoryBytes),
        0
    );
    drop(recovery_in_ordinary_headroom);
    Ok(())
}

#[test]
fn ordinary_and_recovery_shared_occupancy_are_dual_and_reconcile_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(40)?;
    let kernel = establish(tenant, 10, 2)?;
    let ordinary = fill_ordinary(&kernel, tenant)?;
    let mut recovery = kernel.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let protected = kernel.inspect()?;
    assert_eq!(
        protected.recovery_shared_usage(ResourceDimension::MemoryBytes),
        0
    );
    assert_eq!(
        protected.recovery_pool_usage(
            RecoveryWorkKind::SafeShutdown,
            ResourceDimension::MemoryBytes,
        ),
        1
    );
    assert_eq!(
        protected.recovery_pool_capacity(
            RecoveryWorkKind::SafeShutdown,
            ResourceDimension::MemoryBytes,
        ),
        1
    );

    drop(ordinary);
    let full_ordinary_beside_protected = fill_ordinary(&kernel, tenant)?;
    assert_eq!(kernel.inspect()?.usage(ResourceDimension::MemoryBytes), 9);
    drop(full_ordinary_beside_protected);

    recovery.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 8)?)?;
    let shared = kernel.inspect()?;
    assert_eq!(
        shared.recovery_shared_usage(ResourceDimension::MemoryBytes),
        8
    );
    assert_eq!(
        shared.recovery_pool_usage(
            RecoveryWorkKind::SafeShutdown,
            ResourceDimension::MemoryBytes,
        ),
        0
    );
    let occupied = kernel
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::SecurityLifecycle,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("recovery Shared usage reduces the ordinary ceiling");
    assert_eq!(
        occupied.code(),
        AdmissionFailureCode::CapacityOccupiedByRecovery
    );
    assert_eq!(occupied.allowed(), 0);
    assert_eq!(occupied.in_use(), 0);
    assert_eq!(occupied.requested(), 1);

    recovery.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 7)?)?;
    let ordinary = kernel.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let resize = recovery
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 9)?)
        .expect_err("ordinary occupancy reduces recovery Shared resize availability");
    assert_eq!(
        resize.admission_code(),
        Some(AdmissionFailureCode::RecoveryReserveExhausted)
    );
    assert_eq!(
        resize.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
    assert_eq!(recovery.granted().get(ResourceDimension::MemoryBytes), 7);

    drop(ordinary);
    recovery.cancel()?;
    let reconciled = kernel.inspect()?;
    assert_eq!(reconciled.outstanding_total(), 0);
    assert_eq!(
        reconciled.recovery_shared_usage(ResourceDimension::MemoryBytes),
        0
    );
    assert_eq!(
        reconciled.recovery_pool_usage(
            RecoveryWorkKind::SafeShutdown,
            ResourceDimension::MemoryBytes,
        ),
        0
    );
    Ok(())
}

#[test]
fn recovery_total_ceiling_and_attribution_are_bounded_with_stable_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let known_tenant = tenant(23)?;
    let peer_tenant = tenant(25)?;
    let foreign = tenant(24)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(30),
                16,
                2,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(30),
                16,
                2,
            )?,
        )?,
        RecoveryReserve::new(uniform(18))?,
        InventoryCardinalityLimits::new(2, 16)?,
        disk_thresholds(18)?,
        DiskObservation::new(30),
    )?;
    let kernel = TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new(
            [
                TenantQuota::new(known_tenant, 1, uniform(12))?,
                TenantQuota::new(peer_tenant, 1, uniform(12))?,
            ],
            OrdinaryPoolPolicy::new(uniform(3), uniform(3), uniform(2), uniform(2))?,
        )?,
        RecoveryPoolCapacities::new(
            uniform(3),
            uniform(2),
            uniform(3),
            uniform(2),
            uniform(3),
            uniform(3),
            uniform(2),
        )?,
    )?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let full = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 13)?,
    )?)?;
    let failure = recovery
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::EmergencyCompaction,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("system recovery cannot consume the tenant's protected kind floor");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::ProtectedCapacityUnavailable
    );
    assert_eq!(failure.retry(), AdmissionRetry::AfterCapacityRelease);
    assert_eq!(failure.limiting_scope(), LimitingScope::ProtectedReserve);
    assert_eq!(failure.allowed(), 13);
    assert_eq!(failure.in_use(), 13);
    assert_eq!(failure.requested(), 1);

    let durability = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let fencing = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::Fencing,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 3)?,
    )?)?;
    let shutdown = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
    )?)?;
    let tenant_compaction = recovery.reserve(RecoveryWorkClaim::tenant(
        known_tenant,
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let retention = recovery.reserve(RecoveryWorkClaim::tenant(
        known_tenant,
        RecoveryWorkKind::Retention,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let purge = recovery.reserve(RecoveryWorkClaim::tenant(
        known_tenant,
        RecoveryWorkKind::Purge,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let repair = recovery.reserve(RecoveryWorkClaim::tenant(
        known_tenant,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;

    for (scope, kind) in [
        (
            RecoveryScope::System,
            RecoveryWorkKind::DurabilityCompletion,
        ),
        (
            RecoveryScope::Tenant(known_tenant),
            RecoveryWorkKind::Retention,
        ),
        (RecoveryScope::System, RecoveryWorkKind::EmergencyCompaction),
        (RecoveryScope::Tenant(known_tenant), RecoveryWorkKind::Purge),
        (
            RecoveryScope::Tenant(known_tenant),
            RecoveryWorkKind::Repair,
        ),
        (RecoveryScope::System, RecoveryWorkKind::Fencing),
        (RecoveryScope::System, RecoveryWorkKind::SafeShutdown),
    ] {
        let claim = match scope {
            RecoveryScope::System => RecoveryWorkClaim::system(
                kind,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            ),
            RecoveryScope::Tenant(tenant) => RecoveryWorkClaim::tenant(
                tenant,
                kind,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            ),
        }?;
        let isolated = match recovery.reserve(claim) {
            Err(failure) => failure,
            Ok(grant) => {
                drop(grant);
                panic!("{kind:?} escaped its isolated protected pool")
            },
        };
        match scope {
            RecoveryScope::System => assert!(matches!(
                isolated.code(),
                AdmissionFailureCode::ProtectedCapacityUnavailable
                    | AdmissionFailureCode::RecoveryReserveExhausted
            )),
            RecoveryScope::Tenant(_) => {
                assert_eq!(
                    isolated.code(),
                    AdmissionFailureCode::TenantFairShareExceeded
                );
            },
        }
    }

    let attribution_failure = recovery
        .reserve(RecoveryWorkClaim::tenant(
            foreign,
            RecoveryWorkKind::Retention,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("recovery attribution must be in the bounded tenant table");
    assert_eq!(
        attribution_failure.code(),
        AdmissionFailureCode::UnregisteredTenant
    );
    assert_eq!(attribution_failure.limiting_scope(), LimitingScope::Tenant);
    drop((
        full,
        durability,
        fencing,
        shutdown,
        tenant_compaction,
        retention,
        purge,
        repair,
    ));
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn recovery_kind_derives_scope_class_and_interruption_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(25)?;
    let system = RecoveryWorkClaim::system(
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::IoPermits, 1)?,
    )?;
    assert_eq!(system.scope(), RecoveryScope::System);
    assert_eq!(
        RecoveryWorkKind::DurabilityCompletion.interruption(),
        RecoveryInterruption::RetainUntilCompletion
    );
    assert_eq!(
        RecoveryWorkKind::Repair.interruption(),
        RecoveryInterruption::CooperativeAtCheckpoint
    );
    let attributed = RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Purge,
        ResourceAmounts::only(ResourceDimension::TaskSlots, 1)?,
    )?;
    assert_eq!(attributed.scope(), RecoveryScope::Tenant(tenant));
    assert_eq!(
        GovernorFailure::InvalidRecoveryScope.to_string(),
        "recovery work kind is invalid for the requested scope"
    );
    assert_eq!(
        GovernorFailure::GovernorContended {
            pressure: DiskPressureState::Healthy,
        }
        .to_string(),
        "resource governor is contended"
    );
    assert_eq!(
        RecoveryWorkClaim::system(
            RecoveryWorkKind::Purge,
            ResourceAmounts::only(ResourceDimension::TaskSlots, 1)?,
        ),
        Err(GovernorFailure::InvalidRecoveryScope)
    );
    assert_eq!(
        RecoveryWorkClaim::tenant(
            tenant,
            RecoveryWorkKind::Fencing,
            ResourceAmounts::only(ResourceDimension::TaskSlots, 1)?,
        ),
        Err(GovernorFailure::InvalidRecoveryScope)
    );
    assert_eq!(
        RecoveryWorkClaim::system(
            RecoveryWorkKind::Retention,
            ResourceAmounts::only(ResourceDimension::TaskSlots, 1)?,
        ),
        Err(GovernorFailure::InvalidRecoveryScope)
    );
    assert_eq!(
        RecoveryWorkClaim::tenant(
            tenant,
            RecoveryWorkKind::SafeShutdown,
            ResourceAmounts::only(ResourceDimension::TaskSlots, 1)?,
        ),
        Err(GovernorFailure::InvalidRecoveryScope)
    );
    assert_eq!(
        RecoveryWorkClaim::system(RecoveryWorkKind::Repair, ResourceAmounts::new([0; 11]),),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        RecoveryWorkClaim::tenant(
            tenant,
            RecoveryWorkKind::Repair,
            ResourceAmounts::new([0; 11]),
        ),
        Err(GovernorFailure::InvalidConfiguration)
    );
    Ok(())
}

#[test]
fn recovery_reserve_must_be_positive_and_fit_effective_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(26)?;
    assert!(RecoveryReserve::new(ResourceAmounts::new([0; 11])).is_err());
    assert_eq!(
        RecoveryPoolCapacities::new(
            ResourceAmounts::new([0; 11]),
            uniform(1),
            uniform(1),
            uniform(1),
            uniform(1),
            uniform(1),
            uniform(1),
        ),
        Err(GovernorFailure::InvalidConfiguration)
    );
    let oversized = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(10),
            1,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(10),
            1,
        )?)?,
        RecoveryReserve::new(uniform(11))?,
        InventoryCardinalityLimits::new(1, 1)?,
        disk_thresholds(11)?,
        DiskObservation::new(10),
    );
    assert!(oversized.is_err());

    let inventory = ResourceInventory::new(
        DetectedCapacity::new(uniform(10))?,
        OperatorLimits::new(uniform(10))?,
        RecoveryReserve::new(uniform(2))?,
        InventoryCardinalityLimits::new(1, 1)?,
        disk_thresholds(2)?,
        DiskObservation::new(10),
    )?;
    let result = TestKernel::establish(
        inventory,
        GovernorPolicy::new([TenantQuota::new(tenant, 1, uniform(9))?], pool_policy()?)?,
    );
    assert!(
        result.is_err(),
        "tenant quota may not include protected capacity"
    );
    Ok(())
}

#[test]
fn recovery_arithmetic_overflow_is_total_exhaustion_not_internal_fencing()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(27)?;
    let cardinality = InventoryCardinalityLimits::new(1, 7)?;
    let overhead = cardinality.governor_bootstrap_memory_bytes(1)?;
    let total = ResourceAmounts::new([u64::MAX, 18, 18, 18, 18, 18, 18, 18, 18, 20, 18]);
    let reserve = ResourceAmounts::new([10; 11]);
    let ordinary = ResourceAmounts::new([u64::MAX - overhead - 10, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(total)?,
        OperatorLimits::new(total)?,
        RecoveryReserve::new(reserve)?,
        cardinality,
        disk_thresholds(10)?,
        DiskObservation::new(18),
    )?;
    let kernel = TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new([TenantQuota::new(tenant, 1, ordinary)?], pool_policy()?)?,
        resource_governor_support::recovery_pools()?,
    )?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let full = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, u64::MAX - overhead - 9)?,
    )?)?;
    let failure = recovery
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::SafeShutdown,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("overflow beyond u64::MAX is exact total exhaustion");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::RecoveryReserveExhausted
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::RecoveryReserve);
    assert_eq!(failure.allowed(), u64::MAX - overhead - 9);
    assert_eq!(failure.in_use(), u64::MAX - overhead - 9);
    assert_eq!(failure.requested(), 1);
    drop(full);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    assert_eq!(
        RecoveryPoolCapacities::new(
            uniform(u64::MAX),
            uniform(u64::MAX),
            uniform(1),
            uniform(1),
            uniform(1),
            uniform(1),
            uniform(1),
        ),
        Err(GovernorFailure::InvalidConfiguration)
    );
    Ok(())
}

#[test]
fn live_zero_headroom_refuses_disk_growing_emergency_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(33)?;
    let kernel = establish(tenant, 100, 10)?;
    let governor = &kernel;
    let recovery = kernel.recovery();

    governor.observe_disk(DiskObservation::new(0))?;
    let failure = recovery
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::EmergencyCompaction,
            ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 1)?,
        )?)
        .expect_err("live zero usable headroom must refuse disk growth");

    assert_eq!(
        failure.limiting_dimension(),
        Some(ResourceDimension::DiskHeadroomBytes)
    );
    assert_eq!(failure.allowed(), 0);
    assert_eq!(failure.in_use(), 0);
    assert_eq!(failure.requested(), 1);
    assert_eq!(failure.pressure_state(), DiskPressureState::HardPressure);
    Ok(())
}

#[test]
fn tenant_recovery_is_bounded_by_combined_quota_and_weighted_fair_share()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(34)?;
    let second = tenant(35)?;
    let reserve = 24;
    let total = 114;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                16,
                2,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                16,
                2,
            )?,
        )?,
        RecoveryReserve::new(uniform(reserve))?,
        InventoryCardinalityLimits::new(2, 16)?,
        disk_thresholds(reserve)?,
        DiskObservation::new(total),
    )?;
    let kernel = TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new(
            [
                TenantQuota::new(first, 1, uniform(50))?,
                TenantQuota::new(second, 1, uniform(90))?,
            ],
            pool_policy()?,
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
    )?;
    let recovery = kernel.recovery();

    let mut first_grant = recovery.reserve(RecoveryWorkClaim::tenant(
        first,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 49)?,
    )?)?;
    let resize_failure = first_grant
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?)
        .expect_err("a resize cannot take another tenant's recovery share");
    assert_eq!(
        resize_failure.admission_code(),
        Some(AdmissionFailureCode::TenantFairShareExceeded)
    );
    assert_eq!(
        resize_failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    let first_grant = recovery.reserve(RecoveryWorkClaim::tenant(
        first,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 49)?,
    )?)?;
    let first_failure = recovery
        .reserve(RecoveryWorkClaim::tenant(
            first,
            RecoveryWorkKind::Repair,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("one tenant cannot consume another tenant's recovery share");
    assert_eq!(
        first_failure.code(),
        AdmissionFailureCode::TenantFairShareExceeded
    );
    assert_eq!(first_failure.allowed(), 49);
    assert_eq!(first_failure.in_use(), 49);
    let second_grant = recovery.reserve(RecoveryWorkClaim::tenant(
        second,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 49)?,
    )?)?;
    drop((first_grant, second_grant));

    let existing_recovery = recovery.reserve(RecoveryWorkClaim::tenant(
        first,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 26)?,
    )?)?;
    let ordinary = kernel.reserve(WorkClaim::tenant(
        first,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 19)?,
    )?)?;
    let quota_failure = recovery
        .reserve(RecoveryWorkClaim::tenant(
            first,
            RecoveryWorkKind::Repair,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 6)?,
        )?)
        .expect_err("ordinary and recovery use share one absolute tenant quota");
    assert_eq!(
        quota_failure.code(),
        AdmissionFailureCode::TenantQuotaExceeded
    );
    assert_eq!(quota_failure.allowed(), 50);
    assert_eq!(quota_failure.in_use(), 45);
    assert_eq!(quota_failure.requested(), 6);
    drop((ordinary, existing_recovery));
    Ok(())
}

#[test]
fn tiny_tenant_quota_cannot_take_free_global_recovery_but_system_recovery_can()
-> Result<(), Box<dyn std::error::Error>> {
    let small = tenant(36)?;
    let large = tenant(37)?;
    let reserve = resource_governor_support::minimum_recovery_reserve_for_tenants(2)?;
    let total = 90_u64.checked_add(reserve).ok_or("total overflow")?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                16,
                2,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                16,
                2,
            )?,
        )?,
        RecoveryReserve::new(uniform(reserve))?,
        InventoryCardinalityLimits::new(2, 16)?,
        disk_thresholds(reserve)?,
        DiskObservation::new(total),
    )?;
    let kernel = TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new(
            [
                TenantQuota::new(small, 1, uniform(1))?,
                TenantQuota::new(large, 1, uniform(90))?,
            ],
            pool_policy()?,
        )?,
        resource_governor_support::recovery_pools_for_tenants(2)?,
    )?;
    let failure = kernel
        .recovery()
        .reserve(RecoveryWorkClaim::tenant(
            small,
            RecoveryWorkKind::Purge,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("a tiny tenant quota must bind despite unused global capacity");
    assert_eq!(failure.code(), AdmissionFailureCode::TenantQuotaExceeded);
    assert_eq!(failure.allowed(), 1);

    let system = kernel.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 91)?,
    )?)?;
    drop(system);
    Ok(())
}

#[test]
fn tenant_recovery_resize_failure_obeys_interruption_and_releases_all_attribution()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(38)?;
    let kernel = establish(tenant, 100, 10)?;
    let ordinary = kernel.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 10)?,
    )?)?;
    let mut checkpointable = kernel.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 80)?,
    )?)?;
    checkpointable.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 70)?)?;
    checkpointable.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 80)?)?;
    let failure = checkpointable
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 81)?)
        .expect_err("checkpointable recovery cancels before exceeding combined quota");
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CancelledBeforeLimit
    );
    assert_eq!(
        failure.admission_code(),
        Some(AdmissionFailureCode::TenantQuotaExceeded)
    );
    assert_eq!(kernel.inspect()?.outstanding_recovery(), 0);

    let mut retained = kernel.recovery().reserve(RecoveryWorkClaim::tenant(
        tenant,
        RecoveryWorkKind::DurabilityCompletion,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 80)?,
    )?)?;
    let failure = retained
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 81)?)
        .expect_err("durability completion retains its existing grant");
    assert_eq!(
        failure.existing_capacity(),
        ExistingCapacityDisposition::CapacityRetained
    );
    assert_eq!(kernel.inspect()?.outstanding_recovery(), 1);
    retained.cancel()?;
    drop(ordinary);
    assert_eq!(kernel.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn live_disk_headroom_tracks_observation_reservation_resize_and_release()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(39)?;
    let kernel = establish(tenant, 100, 10)?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let mut grant = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 60)?,
    )?)?;

    governor.observe_disk(DiskObservation::new(30))?;
    assert_eq!(governor.inspect()?.usable_disk_bytes(), 30);
    grant.try_resize(ResourceAmounts::only(
        ResourceDimension::DiskHeadroomBytes,
        30,
    )?)?;
    let failure = recovery
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::EmergencyCompaction,
            ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 1)?,
        )?)
        .expect_err("live observed bytes bind outstanding headroom claims");
    assert_eq!(failure.code(), AdmissionFailureCode::CapacityExhausted);
    assert_eq!(failure.allowed(), 30);
    assert_eq!(failure.in_use(), 30);
    grant.cancel()?;

    let mut replacement = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::EmergencyCompaction,
        ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 30)?,
    )?)?;
    governor.observe_disk(DiskObservation::new(60))?;
    replacement.try_resize(ResourceAmounts::only(
        ResourceDimension::DiskHeadroomBytes,
        60,
    )?)?;
    replacement.cancel()?;
    assert_eq!(
        governor
            .inspect()?
            .usage(ResourceDimension::DiskHeadroomBytes),
        0
    );
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
