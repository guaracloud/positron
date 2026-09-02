use std::error::Error;
use std::path::Path;

use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota,
};

#[allow(dead_code)]
pub fn establish(
    path: &Path,
    tenant: TenantId,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    establish_with_compaction_pool(path, tenant, false)
}

#[allow(dead_code)]
pub fn establish_for_compaction(
    path: &Path,
    tenant: TenantId,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    establish_with_compaction_pool(path, tenant, true)
}

fn establish_with_compaction_pool(
    path: &Path,
    tenant: TenantId,
    large_compaction_pool: bool,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let volume = PrimaryDataVolume::acquire(path, MountQualification::LocalHost)?;
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery = add(add(add(durability, large)?, large)?, uniform(12))?;
    let ordinary = if large_compaction_pool {
        ResourceAmounts::new([
            5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 64, 32, 2_000_000,
        ])
    } else {
        ResourceAmounts::new([
            5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
        ])
    };
    let raw = add(
        add(recovery, ordinary)?,
        cardinality.governor_bootstrap_overhead(1)?,
    )?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery.get(ResourceDimension::DiskHeadroomBytes),
            recovery.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let compaction = if large_compaction_pool {
        ResourceAmounts::new([
            20_000_000, 8, 8, 20_000_000, 1_000, 8, 8, 8, 8, 20, 20_000_000,
        ])
    } else {
        small
    };
    let pools = RecoveryPoolCapacities::new(
        durability,
        small,
        compaction,
        small,
        large,
        small,
        small,
    )?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, pools)?,
    )
    .map_err(|_| "authority establishment failed")?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or("capacity overflow")
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
