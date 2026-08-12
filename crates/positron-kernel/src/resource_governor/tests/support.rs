#![allow(dead_code)]

use positron_kernel::{
    AdmissionFailure, DiskObservation, DiskPressureState, GovernorFailure, GovernorPolicy,
    InventoryCardinalityLimits, RecoveryPoolCapacities, RecoveryWorkKind, ResourceAmounts,
    ResourceDimension, ResourceGovernor, ResourceInventory, ResourceReservation, ResourceSnapshot,
    StorageKernelResourceAuthority, WorkClaim,
};

pub fn recovery_pools() -> Result<RecoveryPoolCapacities, GovernorFailure> {
    recovery_pools_for_tenants(1)
}

pub fn recovery_pools_for_tenants(count: usize) -> Result<RecoveryPoolCapacities, GovernorFailure> {
    let amount = u64::try_from(count).map_err(|_| GovernorFailure::InvalidConfiguration)?;
    let tenant_only = ResourceAmounts::new([amount; 11]);
    let dual = ResourceAmounts::new(
        [amount
            .checked_add(1)
            .ok_or(GovernorFailure::InvalidConfiguration)?; 11],
    );
    let system_only = ResourceAmounts::new([1; 11]);
    RecoveryPoolCapacities::new(
        dual,
        tenant_only,
        dual,
        tenant_only,
        dual,
        system_only,
        system_only,
    )
}

pub fn minimum_recovery_reserve_for_tenants(count: usize) -> Result<u64, GovernorFailure> {
    let pools = recovery_pools_for_tenants(count)?;
    [
        RecoveryWorkKind::DurabilityCompletion,
        RecoveryWorkKind::Retention,
        RecoveryWorkKind::EmergencyCompaction,
        RecoveryWorkKind::Purge,
        RecoveryWorkKind::Repair,
        RecoveryWorkKind::Fencing,
        RecoveryWorkKind::SafeShutdown,
    ]
    .into_iter()
    .try_fold(0_u64, |total, kind| {
        total
            .checked_add(pools.get(kind).get(ResourceDimension::MemoryBytes))
            .ok_or(GovernorFailure::InvalidConfiguration)
    })
}

pub fn raw_capacity_for_governed_work(
    work: ResourceAmounts,
    maximum_outstanding: u32,
) -> Result<ResourceAmounts, GovernorFailure> {
    raw_capacity_for_governed_work_for_tenants(work, maximum_outstanding, 1)
}

pub fn raw_capacity_for_governed_work_for_tenants(
    work: ResourceAmounts,
    maximum_outstanding: u32,
    tenant_count: usize,
) -> Result<ResourceAmounts, GovernorFailure> {
    let cardinality = InventoryCardinalityLimits::new(tenant_count, maximum_outstanding)?;
    let overhead = cardinality.governor_bootstrap_overhead(tenant_count)?;
    let value = |dimension| {
        work.get(dimension)
            .checked_add(overhead.get(dimension))
            .ok_or(GovernorFailure::InvalidConfiguration)
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

pub struct TestKernel {
    authority: StorageKernelResourceAuthority,
}

impl TestKernel {
    pub fn establish(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::establish_with_recovery_pools(inventory, policy, recovery_pools()?)
    }

    pub fn establish_with_recovery_pools(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let authority =
            StorageKernelResourceAuthority::establish_for_test(inventory, policy, recovery_pools)?;
        Ok(Self { authority })
    }

    pub const fn governor(&self) -> ResourceGovernor<'_> {
        self.authority.governor()
    }

    pub const fn recovery(&self) -> positron_kernel::RecoveryAuthority<'_> {
        self.authority.recovery()
    }

    pub fn reserve(&self, claim: WorkClaim) -> Result<ResourceReservation<'_>, AdmissionFailure> {
        self.governor().reserve(claim)
    }

    pub fn inspect(&self) -> Result<ResourceSnapshot, GovernorFailure> {
        self.governor().inspect()
    }

    pub fn observe_disk(
        &self,
        observation: DiskObservation,
    ) -> Result<DiskPressureState, GovernorFailure> {
        self.authority.observe_disk_for_test(observation)
    }

    pub fn begin_shutdown(
        &self,
    ) -> Result<positron_kernel::ShutdownReconciliation, GovernorFailure> {
        self.authority.begin_shutdown()
    }
}
