use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota,
};

use super::{BootstrapFailure, BootstrapFailureCode};

const DIMENSIONS: usize = 11;

pub(super) fn establish(
    volume: OwnedPrimaryDataVolume,
    tenant: TenantId,
) -> Result<StorageKernelResourceAuthority, BootstrapFailure> {
    let cardinality = InventoryCardinalityLimits::new(1, 16).map_err(resource_failure)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])
            .map_err(resource_failure)?,
    )
    .map_err(resource_failure)?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(add(add(durability, large)?, large)?, uniform(12))?;
    let ordinary_capacity = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary_capacity)?;
    let raw = add(
        governed,
        cardinality
            .governor_bootstrap_overhead(1)
            .map_err(resource_failure)?,
    )?;
    let disk = observed.initial_disk().usable_bytes();
    let recovery_disk = recovery_capacity.get(ResourceDimension::DiskHeadroomBytes);
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw).map_err(resource_failure)?,
        RecoveryReserve::new(recovery_capacity).map_err(resource_failure)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_disk,
            recovery_disk.saturating_add(1),
            recovery_disk.saturating_add(2),
            disk,
        )
        .map_err(resource_failure)?,
    )
    .map_err(resource_failure)?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary_capacity).map_err(resource_failure)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))
            .map_err(resource_failure)?,
    )
    .map_err(resource_failure)?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)
            .map_err(resource_failure)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)
        .map_err(resource_failure)?;
    StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; DIMENSIONS])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, BootstrapFailure> {
    let value = |dimension| {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
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

fn resource_failure<T>(_failure: T) -> BootstrapFailure {
    BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable)
}
