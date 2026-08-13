use std::error::Error;

use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota,
};

const DIMENSIONS: usize = 11;

pub fn catalog_recovery_claim() -> ResourceAmounts {
    ResourceAmounts::new([
        70_000_000, 1, 1, 70_000_000, 65_540, 0, 1, 1, 1, 8, 20_000_000,
    ])
}
pub fn establish_catalog_authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
    let large = ResourceAmounts::new([
        70_000_001, 2, 2, 70_000_001, 65_541, 2, 2, 2, 2, 9, 20_000_001,
    ]);
    let small = uniform(1);
    let dual = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(add(add(durability, large)?, large)?, uniform(6))?;
    let ordinary_capacity = uniform(16);
    let governed = add(recovery_capacity, ordinary_capacity)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )
    .map_err(|failure| format!("catalog test inventory: {failure:?}"))?;
    let tenant = TenantId::from_bytes([0x43; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(16))?],
        OrdinaryPoolPolicy::new(uniform(4), uniform(3), uniform(2), uniform(1))?,
    )
    .map_err(|failure| format!("catalog test policy: {failure:?}"))?;
    let recovery = RecoveryPoolCapacities::new(durability, small, dual, small, large, small, small)
        .map_err(|failure| format!("catalog test recovery pools: {failure:?}"))?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)
        .map_err(|failure| format!("catalog test governor configuration: {failure:?}"))?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        configuration,
    )?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; DIMENSIONS])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| -> Result<u64, Box<dyn Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| Box::<dyn Error>::from("catalog test resource capacity overflow"))
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
