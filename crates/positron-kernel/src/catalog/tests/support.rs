use crate::{
    DiskObservation, DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, StorageKernelResourceAuthority, TenantQuota,
};
use positron_domain::identity::TenantId;

pub(super) fn establish_catalog_authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn std::error::Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let large = ResourceAmounts::new([
        70_000_001, 2, 2, 70_000_001, 65_541, 2, 2, 2, 2, 9, 20_000_001,
    ]);
    let small = uniform(1);
    let dual = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(add(add(durability, large)?, large)?, uniform(6))?;
    let governed = add(recovery_capacity, uniform(16))?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let observed = ObservedResourceEnvironment::for_test(
        &volume,
        raw,
        DiskObservation::new(raw.get(ResourceDimension::DiskHeadroomBytes)),
    )?;
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            raw.get(ResourceDimension::DiskHeadroomBytes),
        )?,
    )?;
    let tenant = TenantId::from_bytes([0x43; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(16))?],
        OrdinaryPoolPolicy::new(uniform(4), uniform(3), uniform(2), uniform(1))?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, dual, small, large, small, small)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        configuration,
    )?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(
    left: ResourceAmounts,
    right: ResourceAmounts,
) -> Result<ResourceAmounts, Box<dyn std::error::Error>> {
    let value = |dimension| -> Result<u64, Box<dyn std::error::Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| "catalog test capacity overflow".into())
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
