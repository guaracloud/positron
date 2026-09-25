use positron_domain::identity::{PrincipalId, TenantId};
use positron_kernel::{
    AdmissionFailureCode, DetectedCapacity, DiskObservation, DiskPressureThresholds,
    GovernorFailure, GovernorPolicy, InventoryCardinalityLimits, LimitingScope,
    MAX_OUTSTANDING_RESERVATIONS, MAX_TENANT_QUOTAS, OperatorLimits, OrdinaryPoolPolicy,
    PrincipalQuota, RecoveryReserve, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, TenantQuota, WorkClaim, WorkClass, WorkKind,
};

fn amounts(memory_bytes: u64) -> ResourceAmounts {
    ResourceAmounts::new([memory_bytes, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10])
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn principal(byte: u8) -> Result<PrincipalId, Box<dyn std::error::Error>> {
    Ok(PrincipalId::from_bytes([byte; 16])?)
}

fn pool_policy() -> Result<OrdinaryPoolPolicy, GovernorFailure> {
    OrdinaryPoolPolicy::new(
        ResourceAmounts::new([2; 11]),
        ResourceAmounts::new([2; 11]),
        ResourceAmounts::new([1; 11]),
        ResourceAmounts::new([1; 11]),
    )
}

fn disk_thresholds(reserve: u64) -> Result<DiskPressureThresholds, GovernorFailure> {
    DiskPressureThresholds::new(reserve, reserve + 1, reserve + 2, reserve + 3)
}

fn governor(
    detected: ResourceAmounts,
    operator: ResourceAmounts,
    quotas: impl IntoIterator<Item = TenantQuota>,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
    governor_with_principal_quota(detected, operator, quotas, None)
}

fn governor_with_principal_quota(
    detected: ResourceAmounts,
    operator: ResourceAmounts,
    quotas: impl IntoIterator<Item = TenantQuota>,
    principal_quota: Option<PrincipalQuota>,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
    let quotas = quotas.into_iter().collect::<Vec<_>>();
    let policy = match quotas.as_slice() {
        [one] => GovernorPolicy::new([*one], pool_policy()?)?,
        [one, two] => GovernorPolicy::new([*one, *two], pool_policy()?)?,
        _ => return Err("test governor requires one or two quotas".into()),
    };
    let policy = match principal_quota {
        Some(quota) => policy.with_principal_quota(quota),
        None => policy,
    };
    let supported_tenants = 2;
    let reserve_amount =
        resource_governor_support::minimum_recovery_reserve_for_tenants(supported_tenants)?;
    let reserve = ResourceAmounts::new([reserve_amount; 11]);
    let detected_total = add_reserve(detected, reserve_amount)?;
    let operator_total = add_reserve(operator, reserve_amount)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                detected_total,
                64,
                supported_tenants,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                operator_total,
                64,
                supported_tenants,
            )?,
        )?,
        RecoveryReserve::new(reserve)?,
        InventoryCardinalityLimits::new(2, 64)?,
        disk_thresholds(reserve_amount)?,
        DiskObservation::new(detected_total.get(ResourceDimension::DiskHeadroomBytes)),
    )?;
    TestKernel::establish_with_recovery_pools(
        inventory,
        policy,
        resource_governor_support::recovery_pools_for_tenants(supported_tenants)?,
    )
}

fn add_reserve(
    amounts: ResourceAmounts,
    reserve: u64,
) -> Result<ResourceAmounts, Box<dyn std::error::Error>> {
    let value = |dimension| {
        amounts
            .get(dimension)
            .checked_add(reserve)
            .ok_or("test capacity cannot add protected reserve")
    };
    Ok(ResourceAmounts::new([
        value(ResourceDimension::MemoryBytes)?,
        value(ResourceDimension::QueueSlots)?,
        value(ResourceDimension::TaskSlots)?,
        value(ResourceDimension::BufferCacheBytes)?,
        value(ResourceDimension::BatchItems)?,
        value(ResourceDimension::LeaseSlots)?,
        value(ResourceDimension::RetrySlots)?,
        value(ResourceDimension::IoPermits)?,
        value(ResourceDimension::CpuWorkUnits)?,
        value(ResourceDimension::FileDescriptors)?,
        value(ResourceDimension::DiskHeadroomBytes)?,
    ]))
}

#[test]
fn authenticated_principal_admission_is_bounded_and_released()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(0xa1)?;
    let first_principal = principal(0xa2)?;
    let second_principal = principal(0xa3)?;
    let capacity = amounts(20);
    let governor = governor_with_principal_quota(
        capacity,
        capacity,
        [TenantQuota::new(tenant, 1, capacity)?],
        Some(PrincipalQuota::new(4, capacity, capacity)?),
    )?;
    let claim = |principal| {
        WorkClaim::authenticated(
            tenant,
            principal,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )
    };

    let mut first = Vec::new();
    for _ in 0..4 {
        first.push(governor.reserve(claim(first_principal)?)?);
    }
    first
        .get_mut(0)
        .ok_or("first principal retains a grant")?
        .try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?)?;
    let refusal = governor
        .reserve(claim(first_principal)?)
        .expect_err("one principal reaches the fixed post-auth grant limit");
    assert_eq!(refusal.code(), AdmissionFailureCode::PrincipalQuotaExceeded);
    assert_eq!(refusal.limiting_scope(), LimitingScope::Principal);
    assert_eq!(
        governor.inspect()?.outstanding_reservations(),
        4,
        "a rejected principal claim must not publish a partial charge"
    );

    let second = governor.reserve(claim(second_principal)?)?;
    let released = first.pop().ok_or("first principal retains a grant")?;
    drop(released.transfer());
    let mut replacement = governor.reserve(claim(first_principal)?)?;
    assert_eq!(
        replacement.cancel()?,
        positron_kernel::ReleaseOutcome::Released
    );
    let cancelled_replacement = governor.reserve(claim(first_principal)?)?;
    drop((first, second, cancelled_replacement));
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn principal_quota_bounds_each_operation_and_aggregate_on_resize()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(0xb1)?;
    let principal = principal(0xb2)?;
    let capacity = amounts(20);
    let per_operation = amounts(3);
    let aggregate = amounts(5);
    let governor = governor_with_principal_quota(
        capacity,
        capacity,
        [TenantQuota::new(tenant, 1, capacity)?],
        Some(PrincipalQuota::new(4, per_operation, aggregate)?),
    )?;
    let claim = |memory_bytes| {
        WorkClaim::authenticated(
            tenant,
            principal,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, memory_bytes)?,
        )
    };

    let mut first = governor.reserve(claim(3)?)?;
    let operation = governor
        .reserve(claim(4)?)
        .expect_err("one operation cannot exceed its principal operation ceiling");
    assert_eq!(
        operation.code(),
        AdmissionFailureCode::PrincipalQuotaExceeded
    );
    assert_eq!(operation.limiting_scope(), LimitingScope::Operation);

    let aggregate = governor
        .reserve(claim(3)?)
        .expect_err("one principal cannot bypass the aggregate ceiling with another operation");
    assert_eq!(
        aggregate.code(),
        AdmissionFailureCode::PrincipalQuotaExceeded
    );
    assert_eq!(aggregate.limiting_scope(), LimitingScope::Principal);

    let resize = first
        .try_resize_preserving_capacity(ResourceAmounts::only(ResourceDimension::MemoryBytes, 4)?)
        .expect_err("resize cannot grow a live operation beyond its operation ceiling");
    assert_eq!(
        resize.admission_failure().map(|failure| failure.code()),
        Some(AdmissionFailureCode::PrincipalQuotaExceeded)
    );
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    drop(first);
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn principal_quota_refusals_do_not_accumulate_charges_or_cross_tenants()
-> Result<(), Box<dyn std::error::Error>> {
    let first_tenant = tenant(0xc1)?;
    let second_tenant = tenant(0xc2)?;
    let principal = principal(0xc3)?;
    let capacity = amounts(20);
    let governor = governor_with_principal_quota(
        capacity,
        capacity,
        [
            TenantQuota::new(first_tenant, 1, capacity)?,
            TenantQuota::new(second_tenant, 1, capacity)?,
        ],
        Some(PrincipalQuota::new(4, amounts(3), amounts(3))?),
    )?;
    let claim = |tenant| {
        WorkClaim::authenticated(
            tenant,
            principal,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 3)?,
        )
    };
    let first = governor.reserve(claim(first_tenant)?)?;
    for _ in 0..32 {
        let refusal = governor
            .reserve(claim(first_tenant)?)
            .expect_err("a retry cannot create an uncharged principal operation");
        assert_eq!(refusal.code(), AdmissionFailureCode::PrincipalQuotaExceeded);
        assert_eq!(refusal.limiting_scope(), LimitingScope::Principal);
    }
    assert_eq!(governor.inspect()?.outstanding_reservations(), 1);
    assert_eq!(
        governor
            .inspect()?
            .rejection_count_for(AdmissionFailureCode::PrincipalQuotaExceeded),
        32
    );
    let second = governor.reserve(claim(second_tenant)?)?;
    drop((first, second));
    assert_eq!(governor.inspect()?.outstanding_reservations(), 0);
    Ok(())
}

#[test]
fn enrolling_a_real_tenant_preserves_existing_admission() -> Result<(), Box<dyn std::error::Error>>
{
    let first = tenant(81)?;
    let second = tenant(82)?;
    let capacity = amounts(20);
    let kernel = governor(capacity, capacity, [TenantQuota::new(first, 1, capacity)?])?;
    let reservation = kernel.reserve(WorkClaim::tenant(
        first,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    kernel.enroll_tenant(second, ResourceAmounts::new([1; 11]))?;
    let second_reservation = kernel.reserve(WorkClaim::tenant(
        second,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop(second_reservation);
    drop(reservation);
    Ok(())
}

#[test]
fn pending_tenant_enrollment_denies_work_then_drop_releases_the_slot()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(83)?;
    let second = tenant(84)?;
    let capacity = amounts(20);
    let kernel = governor(capacity, capacity, [TenantQuota::new(first, 1, capacity)?])?;
    let retained = kernel.reserve(WorkClaim::tenant(
        first,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let pending = kernel.prepare_tenant(second, ResourceAmounts::new([1; 11]))?;
    assert_eq!(
        kernel
            .reserve(WorkClaim::tenant(
                second,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?
            )?)
            .expect_err("pending tenant is not admitted")
            .code(),
        AdmissionFailureCode::UnregisteredTenant
    );
    drop(pending);
    kernel.enroll_tenant(second, ResourceAmounts::new([1; 11]))?;
    drop(retained);
    Ok(())
}

#[test]
fn pending_enrollment_serializes_and_activation_opens_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(85)?;
    let second = tenant(86)?;
    let third = tenant(87)?;
    let capacity = amounts(20);
    let kernel = governor(capacity, capacity, [TenantQuota::new(first, 1, capacity)?])?;
    let mut pending = kernel.prepare_tenant(second, ResourceAmounts::new([1; 11]))?;
    assert!(matches!(
        kernel.prepare_tenant(third, ResourceAmounts::new([1; 11])),
        Err(GovernorFailure::GovernorContended { .. })
    ));
    pending.activate();
    let reservation = kernel.reserve(WorkClaim::tenant(
        second,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    drop(reservation);
    assert!(matches!(
        kernel.prepare_tenant(third, ResourceAmounts::new([1; 11])),
        Err(GovernorFailure::InvalidConfiguration)
    ));
    Ok(())
}

#[test]
fn bootstrap_overhead_and_recovery_subtraction_fail_with_exact_inventory_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(19)?;
    let cardinality = InventoryCardinalityLimits::new(1, 6)?;
    let overhead = cardinality.governor_bootstrap_memory_bytes(1)?;
    let policy = || {
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, ResourceAmounts::new([1; 11]))?],
            pool_policy()?,
        )
    };
    for memory in [
        overhead.checked_sub(1).ok_or("positive overhead")?,
        overhead.checked_add(9).ok_or("test memory overflow")?,
        overhead.checked_add(10).ok_or("test memory overflow")?,
    ] {
        let raw = ResourceAmounts::new([memory, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100]);
        let inventory = ResourceInventory::new(
            DetectedCapacity::new(raw)?,
            OperatorLimits::new(raw)?,
            RecoveryReserve::new(ResourceAmounts::new([10; 11]))?,
            cardinality,
            disk_thresholds(10)?,
            DiskObservation::new(100),
        )?;
        assert!(matches!(
            ResourceGovernorConfiguration::new(
                inventory,
                policy()?,
                resource_governor_support::recovery_pools()?,
            ),
            Err(GovernorFailure::GovernorBootstrapInventoryUnavailable {
                required,
            }) if required.get(ResourceDimension::MemoryBytes) == overhead
                && required.get(ResourceDimension::FileDescriptors) == 2
        ));
    }
    Ok(())
}

#[test]
fn reservation_is_atomic_and_drop_returns_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::from_bytes([1; 16])?;
    let capacity = amounts(10);
    let policy = GovernorPolicy::new([TenantQuota::new(tenant, 1, capacity)?], pool_policy()?)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            ResourceAmounts::new([20; 11]),
            64,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            ResourceAmounts::new([20; 11]),
            64,
        )?)?,
        RecoveryReserve::new(ResourceAmounts::new([10; 11]))?,
        InventoryCardinalityLimits::new(1, 64)?,
        disk_thresholds(10)?,
        DiskObservation::new(20),
    )?;
    let governor = TestKernel::establish(inventory, policy)?;

    let first = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 6)?,
    )?)?;

    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
        )?)
        .expect_err("five bytes must not fit while six of ten are reserved");
    assert_eq!(
        failure.limiting_dimension(),
        Some(ResourceDimension::MemoryBytes)
    );
    assert_eq!(failure.allowed(), 10);
    assert_eq!(failure.in_use(), 6);
    assert_eq!(failure.requested(), 5);

    drop(first);
    let _second = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
    )?)?;
    Ok(())
}

#[test]
fn quota_reduction_rejects_new_growth_without_revoking_existing_reservations()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(71)?;
    let capacity = amounts(10);
    let governor = governor(capacity, capacity, [TenantQuota::new(tenant, 1, capacity)?])?;
    let existing = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 6)?,
    )?)?;

    governor.update_tenant_quota(tenant, amounts(5))?;

    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("a quota reduction must stop later growth");
    assert_eq!(failure.code(), AdmissionFailureCode::TenantQuotaExceeded);
    assert_eq!(failure.allowed(), 5);
    assert_eq!(failure.in_use(), 6);
    drop(existing);
    Ok(())
}

#[test]
fn later_dimension_refusal_leaves_earlier_dimensions_uncharged()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(2)?;
    let capacity = ResourceAmounts::new([10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]);
    let governor = governor(capacity, capacity, [TenantQuota::new(tenant, 1, capacity)?])?;
    let disk = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::DiskHeadroomBytes, 6)?,
    )?)?;

    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::new([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]),
        )?)
        .expect_err("disk is the final dimension and must reject atomically");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::ProtectedCapacityUnavailable
    );
    assert_eq!(
        failure.limiting_dimension(),
        Some(ResourceDimension::DiskHeadroomBytes)
    );

    let all_memory = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 6)?,
    )?)?;
    drop((disk, all_memory));
    Ok(())
}

#[test]
fn global_and_tenant_hierarchy_refuse_at_the_exact_scope() -> Result<(), Box<dyn std::error::Error>>
{
    let first_tenant = tenant(3)?;
    let second_tenant = tenant(4)?;
    let global = amounts(20);
    let tenant_limit = amounts(10);
    let tenant_governor = governor(
        global,
        global,
        [
            TenantQuota::new(first_tenant, 1, tenant_limit)?,
            TenantQuota::new(second_tenant, 1, tenant_limit)?,
        ],
    )?;
    let first = tenant_governor.reserve(WorkClaim::tenant(
        first_tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 6)?,
    )?)?;
    let tenant_failure = tenant_governor
        .reserve(WorkClaim::tenant(
            first_tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
        )?)
        .expect_err("tenant quota must bind below the global ceiling");
    assert_eq!(
        tenant_failure.code(),
        AdmissionFailureCode::TenantQuotaExceeded
    );
    assert_eq!(tenant_failure.allowed(), 10);

    drop(first);

    let global_governor = governor(global, global, [TenantQuota::new(first_tenant, 1, global)?])?;
    let security = global_governor.reserve(WorkClaim::tenant(
        first_tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 16)?,
    )?)?;
    let ingest = global_governor.reserve(WorkClaim::tenant(
        first_tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
    )?)?;
    let query = global_governor.reserve(WorkClaim::tenant(
        first_tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let maintenance = global_governor.reserve(WorkClaim::tenant(
        first_tenant,
        WorkKind::OrdinaryMaintenanceBackup,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let global_failure = global_governor
        .reserve(WorkClaim::tenant(
            first_tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("the ordinary global ceiling is already fully occupied");
    assert_eq!(
        global_failure.code(),
        AdmissionFailureCode::ProtectedCapacityUnavailable
    );
    assert_eq!(global_failure.allowed(), 20);
    assert_eq!(global_failure.in_use(), 20);
    drop((security, ingest, query, maintenance));
    Ok(())
}

#[test]
fn effective_capacity_is_the_per_dimension_detected_operator_minimum()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(5)?;
    let detected = ResourceAmounts::new([20, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]);
    let operator = ResourceAmounts::new([10, 20, 10, 10, 10, 10, 10, 10, 10, 10, 10]);
    let quota = ResourceAmounts::new([10; 11]);
    let governor = governor(detected, operator, [TenantQuota::new(tenant, 1, quota)?])?;

    let memory_failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 11)?,
        )?)
        .expect_err("operator memory limit is lower");
    assert_eq!(memory_failure.allowed(), 10);
    let queue_failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::QueueSlots, 11)?,
        )?)
        .expect_err("detected queue capacity is lower");
    assert_eq!(queue_failure.allowed(), 10);
    Ok(())
}

#[test]
fn arithmetic_boundary_is_a_protected_capacity_refusal_not_an_internal_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(6)?;
    let cardinality = InventoryCardinalityLimits::new(1, 6)?;
    let overhead = cardinality.governor_bootstrap_memory_bytes(1)?;
    let total = ResourceAmounts::new([u64::MAX, 20, 20, 20, 20, 20, 20, 20, 20, 22, 20]);
    let reserve = ResourceAmounts::new([10; 11]);
    let ordinary_memory = u64::MAX - overhead - 10;
    let ordinary = ResourceAmounts::new([ordinary_memory, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(total)?,
        OperatorLimits::new(total)?,
        RecoveryReserve::new(reserve)?,
        cardinality,
        disk_thresholds(10)?,
        DiskObservation::new(20),
    )?;
    let governor = TestKernel::establish(
        inventory,
        GovernorPolicy::new([TenantQuota::new(tenant, 1, ordinary)?], pool_policy()?)?,
    )?;
    let first = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, ordinary_memory - 4)?,
    )?)?;
    let ingest = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
    )?)?;
    let query = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::OrdinaryMaintenanceBackup,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("overflow must fail closed as exhaustion");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::ProtectedCapacityUnavailable
    );
    assert_eq!(failure.allowed(), ordinary_memory);
    assert_eq!(failure.in_use(), ordinary_memory - 1);
    assert_eq!(failure.requested(), 2);
    drop((first, ingest, query));
    Ok(())
}

#[test]
fn establishment_rejects_zero_capacity_duplicate_tenants_and_invalid_inventory()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(7)?;
    assert_eq!(
        DetectedCapacity::new(ResourceAmounts::new([0; 11])),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert!(matches!(
        GovernorPolicy::new(
            [
                TenantQuota::new(tenant, 1, amounts(10))?,
                TenantQuota::new(tenant, 1, amounts(10))?,
            ],
            pool_policy()?,
        ),
        Err(GovernorFailure::InvalidConfiguration)
    ));
    assert_eq!(
        InventoryCardinalityLimits::new(0, 1),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        InventoryCardinalityLimits::new(MAX_TENANT_QUOTAS + 1, 1),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        InventoryCardinalityLimits::new(1, MAX_OUTSTANDING_RESERVATIONS + 1),
        Err(GovernorFailure::InvalidConfiguration)
    );

    let above_effective_inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            add_reserve(amounts(10), 7)?,
            1,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            add_reserve(amounts(8), 7)?,
            1,
        )?)?,
        RecoveryReserve::new(ResourceAmounts::new([1; 11]))?,
        InventoryCardinalityLimits::new(1, 1)?,
        disk_thresholds(1)?,
        DiskObservation::new(11),
    )?;
    let above_effective = ResourceGovernorConfiguration::new(
        above_effective_inventory,
        GovernorPolicy::new([TenantQuota::new(tenant, 1, amounts(9))?], pool_policy()?)?,
        resource_governor_support::recovery_pools()?,
    );
    assert!(matches!(
        above_effective,
        Err(GovernorFailure::InvalidConfiguration)
    ));
    Ok(())
}

#[test]
fn inventory_bounds_policy_and_outstanding_reservation_cardinality()
-> Result<(), Box<dyn std::error::Error>> {
    let first_tenant = tenant(9)?;
    let second_tenant = tenant(10)?;
    let capacity = amounts(10);
    let one_tenant_inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            ResourceAmounts::new([17; 11]),
            5,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            ResourceAmounts::new([17; 11]),
            5,
        )?)?,
        RecoveryReserve::new(ResourceAmounts::new([7; 11]))?,
        InventoryCardinalityLimits::new(1, 5)?,
        disk_thresholds(7)?,
        DiskObservation::new(17),
    )?;
    assert!(matches!(
        ResourceGovernorConfiguration::new(
            one_tenant_inventory,
            GovernorPolicy::new(
                [
                    TenantQuota::new(first_tenant, 1, capacity)?,
                    TenantQuota::new(second_tenant, 1, capacity)?,
                ],
                pool_policy()?,
            )?,
            resource_governor_support::recovery_pools()?,
        ),
        Err(GovernorFailure::PolicyCardinalityExceeded)
    ));

    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            ResourceAmounts::new([20; 11]),
            5,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            ResourceAmounts::new([20; 11]),
            5,
        )?)?,
        RecoveryReserve::new(ResourceAmounts::new([10; 11]))?,
        InventoryCardinalityLimits::new(1, 5)?,
        disk_thresholds(10)?,
        DiskObservation::new(20),
    )?;
    let result = ResourceGovernorConfiguration::new(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(first_tenant, 1, capacity)?],
            pool_policy()?,
        )?,
        resource_governor_support::recovery_pools()?,
    );
    assert!(matches!(
        result,
        Err(GovernorFailure::InsufficientOutstandingProgress {
            configured: 5,
            required: 6,
        })
    ));
    Ok(())
}

#[test]
fn work_kind_derives_class_and_empty_claim_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(11)?;
    assert_eq!(
        TenantQuota::new(tenant, 0, ResourceAmounts::new([1; 11])),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 0),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(WorkKind::Ingest.class(), WorkClass::Ingest);
    assert_eq!(
        WorkKind::InteractiveQueryTail.class(),
        WorkClass::InteractiveQueryTail
    );
    assert_eq!(
        WorkClaim::tenant(
            tenant,
            WorkKind::SecurityLifecycle,
            ResourceAmounts::new([0; 11]),
        ),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        GovernorFailure::InvalidConfiguration.to_string(),
        "resource governor configuration is invalid"
    );
    assert_eq!(
        GovernorFailure::PolicyCardinalityExceeded.to_string(),
        "resource governor policy cardinality exceeded"
    );
    assert_eq!(
        GovernorFailure::InternalFenced.to_string(),
        "resource governor internal state is fenced"
    );
    Ok(())
}

#[test]
fn every_registered_resource_dimension_is_charged_and_released_independently()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(8)?;
    let capacity = ResourceAmounts::new([10; 11]);
    for dimension in ResourceDimension::ALL {
        let governor = governor(capacity, capacity, [TenantQuota::new(tenant, 1, capacity)?])?;
        let reservation = governor.reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 6)?,
        )?)?;
        let failure = governor
            .reserve(WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(dimension, 5)?,
            )?)
            .expect_err("the registered dimension must enforce its finite bound");
        assert_eq!(
            failure.code(),
            AdmissionFailureCode::ProtectedCapacityUnavailable
        );
        assert_eq!(failure.limiting_dimension(), Some(dimension));
        assert_eq!(failure.allowed(), 10);
        assert_eq!(failure.in_use(), 6);
        assert_eq!(failure.requested(), 5);
        drop(reservation);
        let released = governor.reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(dimension, 6)?,
        )?)?;
        drop(released);
    }
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
