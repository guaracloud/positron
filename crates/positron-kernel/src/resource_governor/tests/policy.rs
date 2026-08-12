use positron_domain::identity::TenantId;
use positron_kernel::{
    AdmissionFailureCode, DetectedCapacity, DiskObservation, DiskPressureThresholds,
    GovernorFailure, GovernorPolicy, InventoryCardinalityLimits, LimitingScope, OperatorLimits,
    OrdinaryPool, OrdinaryPoolPolicy, RecoveryReserve, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, TenantQuota, WorkClaim, WorkClass, WorkKind,
};

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn disk_thresholds(reserve: u64) -> Result<DiskPressureThresholds, GovernorFailure> {
    DiskPressureThresholds::new(reserve, reserve + 1, reserve + 2, reserve + 3)
}

fn establish_policy_governor(tenant: TenantId) -> Result<TestKernel, Box<dyn std::error::Error>> {
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            16,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(100),
            16,
        )?)?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 16)?,
        disk_thresholds(10)?,
        DiskObservation::new(100),
    )?;
    let governor = TestKernel::establish(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, uniform(90))?],
            pool_policy(20, 15, 10, 5)?,
        )?,
    )?;
    Ok(governor)
}

fn tenant(byte: u8) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_bytes([byte; 16])?)
}

fn pool_policy(
    security: u64,
    ingest: u64,
    query: u64,
    maintenance: u64,
) -> Result<OrdinaryPoolPolicy, GovernorFailure> {
    OrdinaryPoolPolicy::new(
        uniform(security),
        uniform(ingest),
        uniform(query),
        uniform(maintenance),
    )
}

#[test]
fn establishment_derives_one_exact_fixed_pool_partition() -> Result<(), Box<dyn std::error::Error>>
{
    let tenant = tenant(31)?;
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
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(90))?],
        pool_policy(20, 15, 10, 5)?,
    )?;
    let governor = TestKernel::establish(inventory, policy)?;
    let snapshot = governor.inspect()?;
    assert_eq!(
        snapshot.pool_capacity(OrdinaryPool::Shared, ResourceDimension::MemoryBytes),
        40
    );
    assert_eq!(
        snapshot.pool_capacity(
            OrdinaryPool::SecurityLifecycle,
            ResourceDimension::MemoryBytes,
        ),
        20
    );
    assert_eq!(
        snapshot.pool_capacity(OrdinaryPool::Ingest, ResourceDimension::MemoryBytes),
        15
    );
    assert_eq!(
        snapshot.pool_capacity(
            OrdinaryPool::InteractiveQueryTail,
            ResourceDimension::MemoryBytes,
        ),
        10
    );
    assert_eq!(
        snapshot.pool_capacity(
            OrdinaryPool::OrdinaryMaintenanceBackup,
            ResourceDimension::MemoryBytes,
        ),
        5
    );
    Ok(())
}

#[test]
fn pool_policy_rejects_zero_reversed_or_non_strict_ingest_query_headroom() {
    assert_eq!(
        pool_policy(3, 2, 1, 0),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        pool_policy(2, 3, 1, 1),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert_eq!(
        pool_policy(3, 2, 2, 1),
        Err(GovernorFailure::InvalidConfiguration)
    );
    assert!(matches!(
        GovernorPolicy::new([], pool_policy(3, 2, 1, 1).expect("pool policy is valid")),
        Err(GovernorFailure::PolicyCardinalityExceeded)
    ));
}

#[test]
fn establishment_rejects_overflowing_protected_pool_sum() -> Result<(), Box<dyn std::error::Error>>
{
    let tenant = tenant(34)?;
    let maximum = uniform(u64::MAX);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(maximum)?,
        OperatorLimits::new(maximum)?,
        RecoveryReserve::new(uniform(1))?,
        InventoryCardinalityLimits::new(1, 1)?,
        disk_thresholds(1)?,
        DiskObservation::new(u64::MAX),
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(u64::MAX - 1))?],
        OrdinaryPoolPolicy::new(
            uniform(u64::MAX),
            uniform(u64::MAX - 1),
            uniform(u64::MAX - 2),
            uniform(1),
        )?,
    )?;
    assert!(matches!(
        ResourceGovernorConfiguration::new(
            inventory,
            policy,
            resource_governor_support::recovery_pools()?,
        ),
        Err(GovernorFailure::InvalidConfiguration)
    ));
    Ok(())
}

#[test]
fn establishment_rejects_protected_pools_larger_than_ordinary_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(32)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(10),
            8,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(10),
            8,
        )?)?,
        RecoveryReserve::new(uniform(2))?,
        InventoryCardinalityLimits::new(1, 8)?,
        disk_thresholds(2)?,
        DiskObservation::new(10),
    )?;
    let result = ResourceGovernorConfiguration::new(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, uniform(8))?],
            pool_policy(3, 2, 1, 3)?,
        )?,
        resource_governor_support::recovery_pools()?,
    );
    assert!(matches!(result, Err(GovernorFailure::InvalidConfiguration)));
    Ok(())
}

#[test]
fn establishment_rejects_protected_pools_that_leave_no_shared_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(35)?;
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(12),
            8,
        )?)?,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(12),
            8,
        )?)?,
        RecoveryReserve::new(uniform(2))?,
        InventoryCardinalityLimits::new(1, 8)?,
        disk_thresholds(2)?,
        DiskObservation::new(12),
    )?;
    let result = ResourceGovernorConfiguration::new(
        inventory,
        GovernorPolicy::new(
            [TenantQuota::new(tenant, 1, uniform(10))?],
            pool_policy(4, 3, 2, 1)?,
        )?,
        resource_governor_support::recovery_pools()?,
    );
    assert!(matches!(result, Err(GovernorFailure::InvalidConfiguration)));
    Ok(())
}

#[test]
fn query_cannot_consume_ingest_or_maintenance_protected_headroom()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = tenant(33)?;
    let governor = establish_policy_governor(tenant)?;
    let query = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 50)?,
    )?)?;
    let failure = governor
        .reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)
        .expect_err("query may use Shared plus query headroom only");
    assert_eq!(
        failure.code(),
        AdmissionFailureCode::ClassCapacityUnavailable
    );
    assert_eq!(failure.limiting_scope(), LimitingScope::ClassHeadroom);
    assert_eq!(failure.work_class(), WorkClass::InteractiveQueryTail);

    let ingest = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 15)?,
    )?)?;
    let maintenance = governor.reserve(WorkClaim::tenant(
        tenant,
        WorkKind::OrdinaryMaintenanceBackup,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 5)?,
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
    assert_eq!(
        snapshot.pool_usage(OrdinaryPool::Ingest, ResourceDimension::MemoryBytes),
        15
    );
    assert_eq!(
        snapshot.pool_usage(
            OrdinaryPool::OrdinaryMaintenanceBackup,
            ResourceDimension::MemoryBytes,
        ),
        5
    );

    drop((query, ingest, maintenance));
    for pool in [
        OrdinaryPool::Shared,
        OrdinaryPool::Ingest,
        OrdinaryPool::InteractiveQueryTail,
        OrdinaryPool::OrdinaryMaintenanceBackup,
    ] {
        assert_eq!(
            governor
                .inspect()?
                .pool_usage(pool, ResourceDimension::MemoryBytes),
            0
        );
    }
    Ok(())
}
use super::resource_governor_test_support as resource_governor_support;
use resource_governor_support::TestKernel;
