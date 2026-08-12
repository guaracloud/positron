use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionFailureCode, DetectedCapacity, DiskObservation, DiskPressureThresholds,
    GovernorFailure, GovernorPolicy, InventoryCardinalityLimits, LimitingScope, OperatorLimits,
    OrdinaryPool, OrdinaryPoolPolicy, RecoveryReserve, RecoveryScope, RecoveryWorkClaim,
    RecoveryWorkKind, ResourceAmounts, ResourceDimension, ResourceInventory, TenantQuota,
    WorkClaim, WorkClass, WorkKind,
};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn disk_thresholds(reserve: u64) -> Result<DiskPressureThresholds, GovernorFailure> {
    DiskPressureThresholds::new(reserve, reserve + 1, reserve + 2, reserve + 3)
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn pools(
    security: u64,
    ingest: u64,
    query: u64,
    maintenance: u64,
) -> Result<OrdinaryPoolPolicy, Box<dyn std::error::Error>> {
    Ok(OrdinaryPoolPolicy::new(
        uniform(security),
        uniform(ingest),
        uniform(query),
        uniform(maintenance),
    )?)
}

fn two_tenant_governor(
    first: TenantQuota,
    second: TenantQuota,
) -> Result<TestKernel, Box<dyn std::error::Error>> {
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
    let governor = TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new([first, second], pools(20, 15, 10, 5)?)?,
        resource_governor_support::recovery_pools_for_tenants(2)?,
    )?;
    Ok(governor)
}

#[test]
fn equal_weights_receive_deterministic_per_pool_fair_shares()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(41)?;
    let second = tenant(42)?;
    let governor = two_tenant_governor(
        TenantQuota::new(first, 1, uniform(90))?,
        TenantQuota::new(second, 1, uniform(90))?,
    )?;

    let first_grant = governor.reserve(WorkClaim::tenant(
        first,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 25)?,
    )?)?;
    let failure = governor
        .reserve(WorkClaim::tenant(
            first,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("one tenant cannot consume the other tenant's fair share");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::TenantFairShareExceeded
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::TenantFairShare);
    assert_eq!(failure.allowed(), 25);
    assert_eq!(failure.in_use(), 25);
    assert_eq!(failure.requested(), 1);

    let second_grant = governor.reserve(WorkClaim::tenant(
        second,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 25)?,
    )?)?;
    let snapshot = governor.inspect()?;
    assert_eq!(
        snapshot.pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        40
    );
    assert_eq!(
        snapshot.pool_usage(
            OrdinaryPool::InteractiveQueryTail,
            ResourceDimension::MemoryBytes,
        ),
        10
    );
    drop((first_grant, second_grant));
    Ok(())
}

#[test]
fn pressure_cannot_let_one_tenant_consume_another_tenants_protected_share()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(49)?;
    let second = tenant(50)?;
    let governor = two_tenant_governor(
        TenantQuota::new(first, 1, uniform(90))?,
        TenantQuota::new(second, 1, uniform(90))?,
    )?;
    governor.observe_disk(DiskObservation::new(13))?;
    let grant = governor.reserve(WorkClaim::tenant(
        first,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
    )?)?;
    let failure = governor
        .reserve(WorkClaim::tenant(
            first,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("soft pressure preserves the other tenant's protected share");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::DiskPressureAdmissionRefused
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::Policy);
    drop(grant);
    Ok(())
}

#[test]
fn zero_rounded_share_is_rejected_before_authority_establishment()
-> Result<(), Box<dyn std::error::Error>> {
    let small = tenant(43)?;
    let large = tenant(44)?;
    let reserve = resource_governor_support::minimum_recovery_reserve_for_tenants(2)?;
    let total = 8_u64.checked_add(reserve).ok_or("total overflow")?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                7,
                2,
            )?,
        )?,
        OperatorLimits::new(
            resource_governor_support::raw_capacity_for_governed_work_for_tenants(
                uniform(total),
                7,
                2,
            )?,
        )?,
        RecoveryReserve::new(uniform(reserve))?,
        InventoryCardinalityLimits::new(2, 7)?,
        disk_thresholds(reserve)?,
        DiskObservation::new(total),
    )?;
    let result = positron_kernel::ResourceGovernorConfiguration::new(
        inventory,
        GovernorPolicy::new(
            [
                TenantQuota::new(small, 1, uniform(8))?,
                TenantQuota::new(large, u16::MAX, uniform(8))?,
            ],
            pools(2, 2, 1, 1)?,
        )?,
        resource_governor_support::recovery_pools_for_tenants(2)?,
    );
    assert!(matches!(
        result,
        Err(GovernorFailure::TenantProgressUnavailable { tenant, .. }) if tenant == small
    ));
    let failure = GovernorFailure::TenantProgressUnavailable {
        tenant: small,
        class: WorkClass::Ingest,
        dimension: ResourceDimension::MemoryBytes,
    };
    assert_eq!(
        failure.to_string(),
        "resource governor tenant progress is unavailable"
    );
    assert_eq!(
        GovernorFailure::InsufficientOutstandingProgress {
            configured: 5,
            required: 6,
        }
        .to_string(),
        "resource governor outstanding progress is unavailable"
    );
    Ok(())
}

#[test]
fn maximum_capacity_and_weights_do_not_overflow_fair_share_derivation()
-> Result<(), Box<dyn std::error::Error>> {
    const TENANTS: usize = 1_024;
    let maximum_outstanding = u32::try_from(TENANTS)?
        .checked_add(5)
        .ok_or("bound overflow")?;
    let reserve = resource_governor_support::minimum_recovery_reserve_for_tenants(TENANTS)?;
    let overhead = InventoryCardinalityLimits::new(TENANTS, maximum_outstanding)?
        .governor_bootstrap_overhead(TENANTS)?;
    let ordinary_memory = u64::MAX
        .checked_sub(overhead.get(ResourceDimension::MemoryBytes))
        .and_then(|value| value.checked_sub(reserve))
        .ok_or("ordinary memory unavailable")?;
    let ordinary_other = u64::MAX
        .checked_sub(reserve)
        .ok_or("ordinary unavailable")?;
    let quota = ResourceAmounts::new([
        ordinary_memory,
        ordinary_other,
        ordinary_other,
        ordinary_other,
        ordinary_other,
        ordinary_other,
        ordinary_other,
        ordinary_other,
        ordinary_other,
        ordinary_other
            .checked_sub(overhead.get(ResourceDimension::FileDescriptors))
            .ok_or("ordinary descriptors unavailable")?,
        ordinary_other,
    ]);
    let quotas: [TenantQuota; TENANTS] = std::array::from_fn(|index| {
        let mut identity = [0_u8; 16];
        identity[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        let tenant = TenantId::from_bytes(identity).expect("generated identities are valid");
        TenantQuota::new(tenant, u16::MAX, quota).expect("maximum positive quota is valid")
    });
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(uniform(u64::MAX))?,
        OperatorLimits::new(uniform(u64::MAX))?,
        RecoveryReserve::new(uniform(reserve))?,
        InventoryCardinalityLimits::new(TENANTS, maximum_outstanding)?,
        disk_thresholds(reserve)?,
        DiskObservation::new(u64::MAX),
    )?;
    let governor = TestKernel::establish_with_recovery_pools(
        inventory,
        GovernorPolicy::new(quotas, pools(2, 2, 1, 1)?)?,
        resource_governor_support::recovery_pools_for_tenants(TENANTS)?,
    )?;
    assert_eq!(
        governor
            .inspect()?
            .pool_capacity(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        ordinary_memory - 6
    );
    let system = governor.recovery().reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::SafeShutdown,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let kinds = [
        WorkKind::SecurityLifecycle,
        WorkKind::Ingest,
        WorkKind::InteractiveQueryTail,
        WorkKind::OrdinaryMaintenanceBackup,
    ];
    let mut progress = Vec::with_capacity(TENANTS + kinds.len());
    for index in 0..TENANTS {
        let mut identity = [0_u8; 16];
        identity[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        progress.push(governor.reserve(WorkClaim::tenant(
            TenantId::from_bytes(identity)?,
            kinds[index % kinds.len()],
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)?);
    }
    let first_tenant = TenantId::from_bytes({
        let mut identity = [0_u8; 16];
        identity[..8].copy_from_slice(&1_u64.to_le_bytes());
        identity
    })?;
    for kind in kinds {
        progress.push(governor.reserve(WorkClaim::tenant(
            first_tenant,
            kind,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)?);
    }
    assert_eq!(governor.inspect()?.outstanding_total(), maximum_outstanding);
    drop((system, progress));
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn absolute_quota_binds_before_and_after_a_fair_share_charge()
-> Result<(), Box<dyn std::error::Error>> {
    let first = tenant(45)?;
    let second = tenant(46)?;
    let governor = two_tenant_governor(
        TenantQuota::new(first, 1, uniform(15))?,
        TenantQuota::new(second, 1, uniform(90))?,
    )?;
    let before = governor
        .reserve(WorkClaim::tenant(
            first,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 16)?,
        )?)
        .expect_err("absolute quota is checked before fair-share planning");
    assert_eq!(before.code(), AdmissionFailureCode::TenantQuotaExceeded);
    assert_eq!(
        governor
            .inspect()?
            .pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        0
    );

    let grant = governor.reserve(WorkClaim::tenant(
        first,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 15)?,
    )?)?;
    let after = governor
        .reserve(WorkClaim::tenant(
            first,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("absolute quota remains binding after an existing charge");
    assert_eq!(after.code(), AdmissionFailureCode::TenantQuotaExceeded);
    assert_eq!(after.allowed(), 15);
    assert_eq!(after.in_use(), 15);
    drop(grant);
    Ok(())
}

#[test]
fn failed_class_fit_does_not_commit_a_partial_shared_charge()
-> Result<(), Box<dyn std::error::Error>> {
    let primary = tenant(47)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            8,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            8,
        )?)?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 8)?,
        disk_thresholds(10)?,
        DiskObservation::new(100),
    )?;
    let governor = TestKernel::establish(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(primary, 1, uniform(90))?],
            pools(20, 15, 10, 5)?,
        )?,
    )?;
    let security = governor.reserve(WorkClaim::tenant(
        primary,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 39)?,
    )?)?;
    assert_eq!(
        governor
            .inspect()?
            .pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        39
    );
    let failure = governor
        .reserve(WorkClaim::tenant(
            primary,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 12)?,
        )?)
        .expect_err("one Shared unit plus ten query units cannot fit a twelve-unit claim");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::ClassCapacityUnavailable
    );
    assert_eq!(
        governor.inspect()?.pool_usage(
            OrdinaryPool::InteractiveQueryTail,
            ResourceDimension::MemoryBytes,
        ),
        0
    );
    assert_eq!(
        governor
            .inspect()?
            .pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        39
    );
    let query = governor.reserve(WorkClaim::tenant(
        primary,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 11)?,
    )?)?;
    assert_eq!(
        governor
            .inspect()?
            .pool_usage(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        40
    );
    drop((security, query));
    Ok(())
}

#[test]
fn recovery_occupancy_has_an_exact_ordinary_refusal() -> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(49)?;
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
    let kernel = TestKernel::establish(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, uniform(90))?],
            pools(20, 15, 10, 5)?,
        )?,
    )?;
    let governor = &kernel;
    let recovery = kernel.recovery();
    let recovery_grant = recovery.reserve(RecoveryWorkClaim::system(
        RecoveryWorkKind::Repair,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 60)?,
    )?)?;
    assert_eq!(
        RecoveryWorkClaim::system(
            RecoveryWorkKind::Repair,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?
        .scope(),
        RecoveryScope::System
    );
    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
        )?)
        .expect_err("recovery Shared occupancy leaves only thirty ordinary units");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::CapacityOccupiedByRecovery
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::RecoveryOccupancy);
    assert_eq!(failure.allowed(), 30);
    assert_eq!(failure.in_use(), 0);
    assert_eq!(failure.requested(), 50);
    drop(recovery_grant);
    let ordinary = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    drop(ordinary);
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
