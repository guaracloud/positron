use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume,
    PrincipalQuota, RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds,
    ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota,
};

use super::{BootstrapFailure, BootstrapFailureCode};

const DIMENSIONS: usize = 11;
const DEFAULT_TENANT_QUOTA: [u64; DIMENSIONS] = [
    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
];
// These are conservative engineering defaults under the existing tenant and
// class-pool policy, not product-specified constants. The operation vector is
// large enough for the largest currently admissible query lane and the 4 MiB /
// 1,024-record OTLP receiver claim. The aggregate is deliberately identical:
// it preserves existing valid single-query and receiver budgets while keeping
// a Principal's combined live usage finite. QueryBudget and receiver-specific
// limits remain tighter where they apply.
const DEFAULT_PRINCIPAL_OPERATION_QUOTA: [u64; DIMENSIONS] = [
    16_000_000, 16, 16, 5_000_000, 2_000, 16, 16, 16, 16, 16, 1_000_000,
];
const DEFAULT_PRINCIPAL_AGGREGATE_QUOTA: [u64; DIMENSIONS] = DEFAULT_PRINCIPAL_OPERATION_QUOTA;
const DEFAULT_PRINCIPAL_MAXIMUM_OPERATIONS: u32 = 4;

struct ResourceSizing {
    cardinality: InventoryCardinalityLimits,
    recovery_capacity: ResourceAmounts,
    per_tenant_ordinary_capacity: ResourceAmounts,
    raw: ResourceAmounts,
    recovery: RecoveryPoolCapacities,
}

pub(super) const fn initial_tenant_quota() -> [u64; DIMENSIONS] {
    DEFAULT_TENANT_QUOTA
}

pub(super) fn establish(
    volume: OwnedPrimaryDataVolume,
    tenant: TenantId,
    max_registered_tenants: u16,
) -> Result<StorageKernelResourceAuthority, BootstrapFailure> {
    let sizing = resource_sizing(max_registered_tenants)?;
    let observed =
        ObservedResourceEnvironment::observe(&volume, registered_resource_bounds(sizing.raw)?)
            .map_err(resource_failure)?;
    let configuration = resource_configuration(tenant, sizing, observed)?;
    StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))
}

fn resource_sizing(max_registered_tenants: u16) -> Result<ResourceSizing, BootstrapFailure> {
    let max_registered_tenants = usize::from(max_registered_tenants);
    let cardinality =
        InventoryCardinalityLimits::new(max_registered_tenants, 16).map_err(resource_failure)?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = uniform(2);
    let tenant_recovery = uniform(u64::try_from(max_registered_tenants).map_err(resource_failure)?);
    let dual_scope_recovery = uniform(
        u64::try_from(max_registered_tenants)
            .map_err(resource_failure)?
            .checked_add(1)
            .ok_or_else(|| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?,
    );
    let durability = at_least(add(add(large, large)?, large)?, dual_scope_recovery);
    let retention = at_least(small, tenant_recovery);
    let compaction = at_least(uniform(3), dual_scope_recovery);
    let purge = at_least(small, tenant_recovery);
    let repair = at_least(large, dual_scope_recovery);
    let fencing = small;
    let shutdown = small;
    let recovery_capacity = recovery_reserve(RecoveryReserveTerms {
        durability,
        retention,
        compaction,
        purge,
        repair,
        fencing,
        shutdown,
        baseline_slack: large,
    })?;
    let per_tenant_ordinary_capacity = ResourceAmounts::new(DEFAULT_TENANT_QUOTA);
    let ordinary_capacity = multiply(per_tenant_ordinary_capacity, max_registered_tenants)?;
    let governed = add(recovery_capacity, ordinary_capacity)?;
    let raw = add(
        governed,
        cardinality
            .governor_bootstrap_overhead(max_registered_tenants)
            .map_err(resource_failure)?,
    )?;
    let recovery = RecoveryPoolCapacities::new(
        durability, retention, compaction, purge, repair, fencing, shutdown,
    )
    .map_err(resource_failure)?;
    Ok(ResourceSizing {
        cardinality,
        recovery_capacity,
        per_tenant_ordinary_capacity,
        raw,
        recovery,
    })
}

fn resource_configuration(
    tenant: TenantId,
    sizing: ResourceSizing,
    observed: ObservedResourceEnvironment,
) -> Result<ResourceGovernorConfiguration, BootstrapFailure> {
    let disk = observed.initial_disk().usable_bytes();
    let recovery_disk = sizing
        .recovery_capacity
        .get(ResourceDimension::DiskHeadroomBytes);
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(sizing.raw).map_err(resource_failure)?,
        RecoveryReserve::new(sizing.recovery_capacity).map_err(resource_failure)?,
        sizing.cardinality,
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
        [
            TenantQuota::new(tenant, 1, sizing.per_tenant_ordinary_capacity)
                .map_err(resource_failure)?,
        ],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))
            .map_err(resource_failure)?,
    )
    .map_err(resource_failure)?
    .with_principal_quota(
        PrincipalQuota::new(
            DEFAULT_PRINCIPAL_MAXIMUM_OPERATIONS,
            ResourceAmounts::new(DEFAULT_PRINCIPAL_OPERATION_QUOTA),
            ResourceAmounts::new(DEFAULT_PRINCIPAL_AGGREGATE_QUOTA),
        )
        .map_err(resource_failure)?,
    );
    ResourceGovernorConfiguration::new(inventory, policy, sizing.recovery).map_err(resource_failure)
}

fn registered_resource_bounds(
    aggregate_capacity: ResourceAmounts,
) -> Result<RegisteredResourceBounds, BootstrapFailure> {
    RegisteredResourceBounds::new([
        aggregate_capacity.get(ResourceDimension::QueueSlots),
        aggregate_capacity.get(ResourceDimension::TaskSlots),
        aggregate_capacity.get(ResourceDimension::BufferCacheBytes),
        aggregate_capacity.get(ResourceDimension::BatchItems),
        aggregate_capacity.get(ResourceDimension::LeaseSlots),
        aggregate_capacity.get(ResourceDimension::RetrySlots),
        aggregate_capacity.get(ResourceDimension::IoPermits),
    ])
    .map_err(resource_failure)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; DIMENSIONS])
}

fn at_least(left: ResourceAmounts, right: ResourceAmounts) -> ResourceAmounts {
    ResourceAmounts::new([
        left.get(ResourceDimension::MemoryBytes)
            .max(right.get(ResourceDimension::MemoryBytes)),
        left.get(ResourceDimension::QueueSlots)
            .max(right.get(ResourceDimension::QueueSlots)),
        left.get(ResourceDimension::TaskSlots)
            .max(right.get(ResourceDimension::TaskSlots)),
        left.get(ResourceDimension::BufferCacheBytes)
            .max(right.get(ResourceDimension::BufferCacheBytes)),
        left.get(ResourceDimension::BatchItems)
            .max(right.get(ResourceDimension::BatchItems)),
        left.get(ResourceDimension::LeaseSlots)
            .max(right.get(ResourceDimension::LeaseSlots)),
        left.get(ResourceDimension::RetrySlots)
            .max(right.get(ResourceDimension::RetrySlots)),
        left.get(ResourceDimension::IoPermits)
            .max(right.get(ResourceDimension::IoPermits)),
        left.get(ResourceDimension::CpuWorkUnits)
            .max(right.get(ResourceDimension::CpuWorkUnits)),
        left.get(ResourceDimension::FileDescriptors)
            .max(right.get(ResourceDimension::FileDescriptors)),
        left.get(ResourceDimension::DiskHeadroomBytes)
            .max(right.get(ResourceDimension::DiskHeadroomBytes)),
    ])
}

struct RecoveryReserveTerms {
    durability: ResourceAmounts,
    retention: ResourceAmounts,
    compaction: ResourceAmounts,
    purge: ResourceAmounts,
    repair: ResourceAmounts,
    fencing: ResourceAmounts,
    shutdown: ResourceAmounts,
    baseline_slack: ResourceAmounts,
}

fn recovery_reserve(terms: RecoveryReserveTerms) -> Result<ResourceAmounts, BootstrapFailure> {
    let RecoveryReserveTerms {
        durability,
        retention,
        compaction,
        purge,
        repair,
        fencing,
        shutdown,
        baseline_slack,
    } = terms;
    let protected = add(
        add(add(durability, retention)?, add(compaction, purge)?)?,
        add(add(repair, fencing)?, shutdown)?,
    )?;
    add(add(protected, baseline_slack)?, uniform(1))
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

fn multiply(
    capacity: ResourceAmounts,
    tenants: usize,
) -> Result<ResourceAmounts, BootstrapFailure> {
    let tenants = u64::try_from(tenants)
        .map_err(|_| BootstrapFailure::new(BootstrapFailureCode::ResourceUnavailable))?;
    let value = |dimension| {
        capacity
            .get(dimension)
            .checked_mul(tenants)
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use positron_domain::identity::PrincipalId;
    use positron_kernel::{
        DiskObservation, MountQualification, PrimaryDataVolume, WorkClaim, WorkKind,
    };

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn direct_capacity_values_enforce_kernel_bounds_and_checked_aggregation() {
        assert!(matches!(
            resource_sizing(0),
            Err(failure) if failure.code() == BootstrapFailureCode::ResourceUnavailable
        ));
        assert!(matches!(
            resource_sizing(1_025),
            Err(failure) if failure.code() == BootstrapFailureCode::ResourceUnavailable
        ));
        assert!(matches!(
            multiply(ResourceAmounts::new([u64::MAX; DIMENSIONS]), 2),
            Err(failure) if failure.code() == BootstrapFailureCode::ResourceUnavailable
        ));
    }

    #[test]
    fn default_capacity_preserves_the_existing_recovery_reserve() -> Result<(), BootstrapFailure> {
        let sizing = resource_sizing(2)?;
        assert_eq!(
            sizing.recovery_capacity,
            ResourceAmounts::new([
                450_000_012,
                32,
                32,
                450_000_012,
                350_012,
                32,
                32,
                32,
                32,
                92,
                200_000_012,
            ])
        );
        Ok(())
    }

    #[test]
    fn observed_capacity_below_the_configured_aggregate_refuses_before_serving()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "positron-resource-sizing-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let volume = PrimaryDataVolume::acquire(&root, MountQualification::LocalHost)?;
        let observed = ObservedResourceEnvironment::for_test(
            &volume,
            ResourceAmounts::new([1; DIMENSIONS]),
            DiskObservation::new(1),
        )?;
        let result = resource_configuration(
            TenantId::from_bytes([0x42; 16])?,
            resource_sizing(3)?,
            observed,
        );
        assert!(matches!(
            result,
            Err(failure) if failure.code() == BootstrapFailureCode::ResourceUnavailable
        ));
        drop(volume);
        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn default_principal_policy_preserves_canonical_query_and_receiver_claims()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "positron-principal-resource-sizing-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let volume = PrimaryDataVolume::acquire(&root, MountQualification::LocalHost)?;
        let tenant = TenantId::from_bytes([0x91; 16])?;
        let observed = ObservedResourceEnvironment::observe(
            &volume,
            RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
        )?;
        let configuration = resource_configuration(tenant, resource_sizing(1)?, observed)?;
        let authority = StorageKernelResourceAuthority::establish(volume, configuration)?;
        let principal = PrincipalId::from_bytes([0x92; 16])?;
        let query = authority.governor().reserve(WorkClaim::authenticated(
            tenant,
            principal,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::new([6_850_000, 0, 0, 0, 0, 1, 0, 0, 6, 0, 0]),
        )?)?;
        drop(query);
        let receiver = authority.governor().reserve(WorkClaim::authenticated(
            tenant,
            principal,
            WorkKind::Ingest,
            ResourceAmounts::new([4_194_304, 1, 1, 1_048_576, 1_024, 0, 0, 0, 1, 1, 0]),
        )?)?;
        drop(receiver);
        drop(authority);
        fs::remove_dir_all(&root)?;
        Ok(())
    }
}
