//! Atomic, hierarchical resource admission for the Storage Kernel.

mod accounting;
mod admission;
mod bootstrap;
mod capacity_observation;
mod claim;
mod decision;
mod failure;
mod fairness;
mod inventory;
mod ledger;
mod lifecycle;
#[cfg(test)]
#[path = "resource_governor/tests/lifecycle.rs"]
mod lifecycle_tests;
mod model;
mod option_ext;
mod policy;
mod pool_admission;
mod pressure;
mod recovery_admission;
mod recovery_policy;
mod release;
mod resize;
mod resize_recovery;
mod resize_types;
mod snapshot;
#[cfg(test)]
#[path = "resource_governor/tests/telemetry.rs"]
mod telemetry_tests;
#[cfg(test)]
mod tests;

use accounting::{GovernorConfiguration, GovernorInner, GovernorSetupInput, KernelOwnership};
use bootstrap::{BootstrapAllocationStage, BootstrapInventoryLayout};
#[cfg(fuzzing)]
#[doc(hidden)]
pub use capacity_observation::fuzz_linux_capacity_parsers;
pub use capacity_observation::{
    CAPACITY_OBSERVATION_TRANSIENT_MEMORY_BYTES, CPU_WORK_UNITS_PER_LOGICAL_CPU,
    CapacityObservationFailure, CapacityObservationSource, ObservedResourceEnvironment,
    RegisteredResourceBounds,
};
use claim::ReservationIdentity;
pub use claim::{
    RecoveryInterruption, RecoveryScope, RecoveryWorkClaim, RecoveryWorkKind, WorkClaim, WorkClass,
    WorkKind,
};
pub use failure::{
    AdmissionCompletionState, AdmissionFailure, AdmissionFailureCode, AdmissionRetry,
    DiskPressureState, GovernorFailure, LimitingScope,
};
pub use inventory::{
    DetectedCapacity, DiskObservation, DiskPressureThresholds, InventoryCardinalityLimits,
    MAX_OUTSTANDING_RESERVATIONS, MAX_TENANT_QUOTAS, OperatorLimits, RecoveryReserve,
    ResourceInventory, TenantQuota,
};
pub use lifecycle::{GovernorLifecycle, ReleaseOutcome, ShutdownReconciliation};
pub use model::{RESOURCE_DIMENSION_COUNT, ResourceAmounts, ResourceDimension};
pub use policy::{GovernorPolicy, OrdinaryPool, OrdinaryPoolPolicy};
pub use recovery_policy::RecoveryPoolCapacities;
pub use resize_types::{
    ExistingCapacityDisposition, ResizeFailure, ResizeFailureCode, ResizeOutcome,
};
pub use snapshot::ResourceSnapshot;

/// The single Release 1 authority for bounded resource admission.
///
/// Admission consumers cannot mutate kernel disk or lifecycle state.
///
/// ```compile_fail
/// # use positron_kernel::{DiskObservation, ResourceGovernor};
/// fn mutate(governor: &ResourceGovernor<'_>, observation: DiskObservation) {
///     let _ = governor.observe_disk(observation);
/// }
/// ```
///
/// ```compile_fail
/// # use positron_kernel::ResourceGovernor;
/// fn stop(governor: &ResourceGovernor<'_>) {
///     let _ = governor.begin_shutdown();
/// }
/// ```
#[derive(Clone, Copy)]
pub struct ResourceGovernor<'authority> {
    inner: &'authority GovernorInner,
}

/// The single resource-admission authority bound to one owned Storage Kernel.
///
/// Construction consumes the process-lifetime Primary Data Volume ownership
/// claim, so the same Storage Kernel identity cannot establish a substitute
/// governor. Keep this value alive for the complete kernel lifetime; its field
/// order drops admission authorities before releasing volume ownership.
///
/// ```compile_fail
/// use positron_kernel::StorageKernelResourceAuthority;
/// fn require_clone<T: Clone>() {}
/// require_clone::<StorageKernelResourceAuthority>();
/// ```
///
/// ```compile_fail
/// use positron_kernel::{RecoveryAuthority, StorageKernelResourceAuthority};
/// fn escape(authority: StorageKernelResourceAuthority) -> RecoveryAuthority<'static> {
///     authority.recovery()
/// }
/// ```
///
/// Ordinary admission cannot outlive the sole Storage Kernel authority.
///
/// ```compile_fail
/// use positron_kernel::{StorageKernelResourceAuthority, WorkClaim};
/// fn orphan_admission(authority: StorageKernelResourceAuthority, claim: WorkClaim) {
///     let governor = authority.governor().clone();
///     drop(authority);
///     let _ = governor.reserve(claim);
/// }
/// ```
///
/// A live reservation also keeps the root authority borrowed.
///
/// ```compile_fail
/// use positron_kernel::{StorageKernelResourceAuthority, WorkClaim};
/// fn orphan_reservation(authority: StorageKernelResourceAuthority, claim: WorkClaim) {
///     let reservation = authority.governor().reserve(claim).unwrap();
///     drop(authority);
///     drop(reservation);
/// }
/// ```
pub struct StorageKernelResourceAuthority {
    inner: GovernorInner,
}

impl std::fmt::Debug for StorageKernelResourceAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StorageKernelResourceAuthority { <bounded capability> }")
    }
}

/// Fully validated resource-governor configuration without admission authority.
pub struct ResourceGovernorConfiguration {
    inner: GovernorConfiguration,
    volume_binding: Option<capacity_observation::ObservedVolumeBinding>,
}

/// A recoverable failure to bind a validated governor configuration to its observed volume.
pub struct EstablishmentFailure {
    failure: GovernorFailure,
    volume: crate::OwnedPrimaryDataVolume,
    configuration: ResourceGovernorConfiguration,
}

impl EstablishmentFailure {
    #[must_use]
    pub const fn failure(&self) -> GovernorFailure {
        self.failure
    }

    #[must_use]
    pub fn into_parts(self) -> (crate::OwnedPrimaryDataVolume, ResourceGovernorConfiguration) {
        (self.volume, self.configuration)
    }
}

impl std::fmt::Debug for EstablishmentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EstablishmentFailure { <redacted> }")
    }
}

impl std::fmt::Display for EstablishmentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resource governor establishment failed")
    }
}

impl std::error::Error for EstablishmentFailure {}

/// Governor-bound, non-cloneable authority for protected recovery capacity.
///
/// ```compile_fail
/// use positron_kernel::RecoveryAuthority;
/// fn require_clone<T: Clone>() {}
/// require_clone::<RecoveryAuthority>();
/// ```
pub struct RecoveryAuthority<'authority> {
    inner: &'authority GovernorInner,
}

/// A move-only capacity grant that releases on every terminal path.
pub struct ResourceReservation<'authority> {
    governor: &'authority GovernorInner,
    slot: u16,
    owner: accounting::ChargeOwner,
    identity: ReservationIdentity,
    amounts: ResourceAmounts,
    active: bool,
}

impl std::fmt::Debug for ResourceReservation<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResourceReservation { <bounded capability> }")
    }
}

impl<'authority> ResourceGovernor<'authority> {
    /// Atomically admits one tenant work claim without waiting or queueing.
    pub fn reserve(
        &self,
        claim: WorkClaim,
    ) -> Result<ResourceReservation<'authority>, AdmissionFailure> {
        self.inner.reserve_ordinary(claim)
    }

    /// Returns a bounded snapshot of reservation bookkeeping.
    pub fn inspect(&self) -> Result<ResourceSnapshot, GovernorFailure> {
        let snapshot = self.inner.snapshot()?;
        Ok(ResourceSnapshot::from_accounting(snapshot))
    }
}

impl ResourceGovernorConfiguration {
    /// Validates every capacity, fairness, and cardinality cross-invariant.
    pub fn new(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, GovernorFailure> {
        Self::new_with_failure(inventory, policy, recovery_pools, None)
    }

    fn new_with_failure(
        mut inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
        fail_at: Option<BootstrapAllocationStage>,
    ) -> Result<Self, GovernorFailure> {
        if policy.tenant_quotas.len() > inventory.cardinality.max_tenant_quotas {
            return Err(GovernorFailure::PolicyCardinalityExceeded);
        }
        let layout = BootstrapInventoryLayout::new(
            policy.tenant_quotas.len(),
            inventory.cardinality.max_outstanding_reservations,
        )?;
        let bootstrap_overhead = layout.overhead();
        let unavailable = GovernorFailure::GovernorBootstrapInventoryUnavailable {
            required: bootstrap_overhead,
        };
        let work_ceiling = inventory
            .effective
            .checked_sub(bootstrap_overhead)
            .ok_or(unavailable)?;
        let ordinary_ceiling = work_ceiling
            .checked_sub(inventory.recovery_reserve.amounts())
            .ok_or(unavailable)?;
        if !ordinary_ceiling.all_positive() {
            return Err(unavailable);
        }
        if policy.tenant_quotas.iter().any(|quota| {
            ResourceDimension::ALL
                .iter()
                .any(|dimension| quota.limits.get(*dimension) > ordinary_ceiling.get(*dimension))
        }) {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        let pool_capacities = policy.pools.derive(ordinary_ceiling)?;
        let protected_recovery = recovery_pools
            .protected_sum()
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        if !protected_recovery.is_at_most(inventory.recovery_reserve.amounts()) {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        let volume_binding = inventory.take_volume_binding();
        let inner = GovernorInner::configure(GovernorSetupInput {
            raw_effective: inventory.effective,
            bootstrap_overhead,
            total_ceiling: work_ceiling,
            ordinary_ceiling,
            tenant_quotas: policy.tenant_quotas,
            maximum_outstanding: inventory.cardinality.max_outstanding_reservations,
            pool_capacities,
            recovery_pool_capacities: recovery_pools,
            disk_thresholds: inventory.disk_thresholds,
            initial_disk: inventory.initial_disk,
            layout,
            fail_at,
        })?;
        Ok(Self {
            inner,
            volume_binding,
        })
    }

    #[cfg(test)]
    fn new_failing_allocation(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
        stage: BootstrapAllocationStage,
    ) -> Result<Self, GovernorFailure> {
        Self::new_with_failure(inventory, policy, recovery_pools, Some(stage))
    }
}

impl StorageKernelResourceAuthority {
    #[cfg(test)]
    fn establish_for_test(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, GovernorFailure> {
        let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery_pools)?;
        Ok(Self {
            inner: GovernorInner::new(KernelOwnership::TestOnly, configuration.inner),
        })
    }

    /// Establishes an isolated complete authority for the fuzz harness.
    #[cfg(fuzzing)]
    #[doc(hidden)]
    pub fn establish_for_fuzz(
        inventory: ResourceInventory,
        policy: GovernorPolicy,
        recovery_pools: RecoveryPoolCapacities,
    ) -> Result<Self, GovernorFailure> {
        let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery_pools)?;
        Ok(Self {
            inner: GovernorInner::new(KernelOwnership::TestOnly, configuration.inner),
        })
    }
    /// Establishes the sole governor after earlier private bootstrap/recovery steps.
    #[expect(
        clippy::result_large_err,
        reason = "the recoverable mismatch must return both non-allocating move-only capabilities"
    )]
    pub fn establish(
        volume: crate::OwnedPrimaryDataVolume,
        configuration: ResourceGovernorConfiguration,
    ) -> Result<Self, EstablishmentFailure> {
        if configuration
            .volume_binding
            .as_ref()
            .is_none_or(|binding| !binding.matches(&volume))
        {
            return Err(EstablishmentFailure {
                failure: GovernorFailure::ObservedVolumeMismatch,
                volume,
                configuration,
            });
        }
        Ok(Self {
            inner: GovernorInner::new(KernelOwnership::Owned { volume }, configuration.inner),
        })
    }

    /// Borrows ordinary admission authority without permitting duplication.
    #[must_use]
    pub const fn governor(&self) -> ResourceGovernor<'_> {
        ResourceGovernor { inner: &self.inner }
    }

    /// Borrows the governor-bound protected recovery authority.
    #[must_use]
    pub const fn recovery(&self) -> RecoveryAuthority<'_> {
        RecoveryAuthority { inner: &self.inner }
    }

    #[cfg(test)]
    fn reserve(&self, claim: WorkClaim) -> Result<ResourceReservation<'_>, AdmissionFailure> {
        self.governor().reserve(claim)
    }

    #[cfg(test)]
    fn inspect(&self) -> Result<ResourceSnapshot, GovernorFailure> {
        self.governor().inspect()
    }

    /// Re-observes the retained Primary Data Volume and applies disk pressure.
    pub fn observe_disk(&self) -> Result<DiskPressureState, GovernorFailure> {
        let volume = match &self.inner.ownership {
            KernelOwnership::Owned { volume } => volume,
            #[cfg(any(test, fuzzing))]
            KernelOwnership::TestOnly => {
                return Err(GovernorFailure::PrimaryVolumeObservationUnavailable);
            },
        };
        let usable_bytes = capacity_observation::observe_disk_bytes(volume)
            .map_err(|_| GovernorFailure::PrimaryVolumeObservationUnavailable)?;
        self.inner
            .apply_disk_observation(DiskObservation::from_observed(usable_bytes))
    }

    #[cfg(test)]
    fn observe_disk_for_test(
        &self,
        observation: DiskObservation,
    ) -> Result<DiskPressureState, GovernorFailure> {
        self.inner.apply_disk_observation(observation)
    }

    #[cfg(fuzzing)]
    #[doc(hidden)]
    pub fn observe_disk_for_fuzz(
        &self,
        observation: DiskObservation,
    ) -> Result<DiskPressureState, GovernorFailure> {
        self.inner.apply_disk_observation(observation)
    }

    /// Closes new work without waiting and returns bounded reconciliation state.
    pub fn begin_shutdown(&self) -> Result<ShutdownReconciliation, GovernorFailure> {
        Ok(ShutdownReconciliation {
            snapshot: ResourceSnapshot::from_accounting(self.inner.begin_shutdown()?),
        })
    }
}

impl<'authority> RecoveryAuthority<'authority> {
    /// Reserves protected capacity for a closed recovery-safe work kind.
    pub fn reserve(
        &self,
        claim: RecoveryWorkClaim,
    ) -> Result<ResourceReservation<'authority>, AdmissionFailure> {
        self.inner.reserve_recovery(claim)
    }
}

impl<'authority> ResourceReservation<'authority> {
    fn new(
        governor: &'authority GovernorInner,
        owner: accounting::ChargeOwner,
        identity: ReservationIdentity,
        amounts: ResourceAmounts,
        slot: u16,
    ) -> Self {
        Self {
            governor,
            owner,
            identity,
            amounts,
            slot,
            active: true,
        }
    }

    /// Releases the reservation immediately. Dropping has identical accounting semantics.
    pub fn cancel(&mut self) -> Result<ReleaseOutcome, GovernorFailure> {
        if !self.active {
            return Ok(ReleaseOutcome::AlreadyInactive);
        }
        let status = self
            .governor
            .try_release(self.slot, self.owner, self.identity, self.amounts);
        if status.applied {
            self.active = false;
        }
        status.result
    }

    /// Atomically replaces the grant while preserving immutable work identity.
    pub fn try_resize(
        &mut self,
        new_amounts: ResourceAmounts,
    ) -> Result<ResizeOutcome, ResizeFailure> {
        if !self.active {
            return Err(ResizeFailure::inactive(
                self.identity.class(),
                self.governor.pressure_for_failure(),
            ));
        }
        if new_amounts.is_empty() {
            return Err(ResizeFailure::invalid(
                self.identity.class(),
                self.governor.pressure_for_failure(),
            ));
        }
        match self.governor.resize(resize::ResizeRequest {
            slot: self.slot,
            owner: self.owner,
            identity: self.identity,
            old: self.amounts,
            new: new_amounts,
        }) {
            Ok(commit) => {
                self.owner = commit.owner;
                self.amounts = new_amounts;
                Ok(commit.outcome)
            },
            Err(failure)
                if failure.existing_capacity()
                    == ExistingCapacityDisposition::CancelledBeforeLimit =>
            {
                self.active = false;
                self.amounts = ResourceAmounts::zero();
                Err(failure)
            },
            Err(failure) => Err(failure),
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub const fn granted(&self) -> ResourceAmounts {
        self.amounts
    }

    fn release(&mut self) {
        if self.active {
            self.governor.mark_drop_pending(self.slot);
            self.active = false;
        }
    }
}

impl Drop for ResourceReservation<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
#[path = "resource_governor/tests/invariant.rs"]
mod invariant_tests;
