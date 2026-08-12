//! Explicit capacity sources and bounded tenant policy.

use positron_domain::identity::TenantId;

use super::bootstrap::BootstrapInventoryLayout;
use super::capacity_observation::ObservedVolumeBinding;
use super::failure::GovernorFailure;
use super::model::{ResourceAmounts, ResourceDimension};

/// Implementation cap bounding tenant scans and fixed-cardinality inspection.
pub const MAX_TENANT_QUOTAS: usize = 1_024;
/// Implementation cap for the fixed outstanding-grant counter.
///
/// The governor stores a fixed preallocated grant registry. The cap bounds
/// reconciliation counts and remains within `u16` cardinality so status and
/// adversarial admission cannot grow without a fixed product bound.
pub const MAX_OUTSTANDING_RESERVATIONS: u32 = u16::MAX as u32;

/// Capacity observed by trusted host composition.
///
/// Raw asserted capacity is unavailable to production callers.
///
/// ```compile_fail
/// # use positron_kernel::{DetectedCapacity, ResourceAmounts};
/// let _ = DetectedCapacity::new(ResourceAmounts::new([1; 11]));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectedCapacity(ResourceAmounts);

impl DetectedCapacity {
    /// Raw asserted capacity is confined to deterministic unit/fuzz sources.
    /// Production composition must use [`super::ObservedResourceEnvironment`].
    #[cfg(any(test, fuzzing))]
    pub fn new(amounts: ResourceAmounts) -> Result<Self, GovernorFailure> {
        require_capacity(amounts).map(|()| Self(amounts))
    }

    pub(super) const fn from_observed(amounts: ResourceAmounts) -> Self {
        Self(amounts)
    }

    #[must_use]
    pub const fn amount(self, dimension: ResourceDimension) -> u64 {
        self.0.get(dimension)
    }
}

/// Explicit operator ceilings, which may only lower detected capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorLimits(ResourceAmounts);

impl OperatorLimits {
    pub fn new(amounts: ResourceAmounts) -> Result<Self, GovernorFailure> {
        require_capacity(amounts).map(|()| Self(amounts))
    }
}

/// Configured bounds below finite implementation maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryCardinalityLimits {
    pub(super) max_tenant_quotas: usize,
    pub(super) max_outstanding_reservations: u32,
}

impl InventoryCardinalityLimits {
    pub fn new(
        max_tenant_quotas: usize,
        max_outstanding_reservations: u32,
    ) -> Result<Self, GovernorFailure> {
        if max_tenant_quotas == 0
            || max_tenant_quotas > MAX_TENANT_QUOTAS
            || max_outstanding_reservations == 0
            || max_outstanding_reservations > MAX_OUTSTANDING_RESERVATIONS
        {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            max_tenant_quotas,
            max_outstanding_reservations,
        })
    }

    /// Conservative logical payload plus fixed root bytes retained by the governor.
    pub fn governor_bootstrap_overhead(
        self,
        tenant_quota_count: usize,
    ) -> Result<ResourceAmounts, GovernorFailure> {
        if tenant_quota_count == 0 || tenant_quota_count > self.max_tenant_quotas {
            return Err(GovernorFailure::PolicyCardinalityExceeded);
        }
        Ok(
            BootstrapInventoryLayout::new(tenant_quota_count, self.max_outstanding_reservations)?
                .overhead(),
        )
    }

    /// Memory component of [`Self::governor_bootstrap_overhead`].
    pub fn governor_bootstrap_memory_bytes(
        self,
        tenant_quota_count: usize,
    ) -> Result<u64, GovernorFailure> {
        Ok(self
            .governor_bootstrap_overhead(tenant_quota_count)?
            .get(ResourceDimension::MemoryBytes))
    }
}

/// The complete finite capacity and bookkeeping inventory for one governor.
///
/// Production callers cannot assemble inventory from asserted observations.
///
/// ```compile_fail
/// # use positron_kernel::{DetectedCapacity, DiskObservation, DiskPressureThresholds,
/// # InventoryCardinalityLimits, OperatorLimits, RecoveryReserve, ResourceInventory};
/// fn asserted(
///     detected: DetectedCapacity,
///     operator: OperatorLimits,
///     reserve: RecoveryReserve,
///     cardinality: InventoryCardinalityLimits,
///     thresholds: DiskPressureThresholds,
///     disk: DiskObservation,
/// ) {
///     let _ = ResourceInventory::new(
///         detected, operator, reserve, cardinality, thresholds, disk,
///     );
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct ResourceInventory {
    detected: DetectedCapacity,
    operator: OperatorLimits,
    pub(super) effective: ResourceAmounts,
    pub(super) recovery_reserve: RecoveryReserve,
    pub(super) cardinality: InventoryCardinalityLimits,
    pub(super) disk_thresholds: DiskPressureThresholds,
    pub(super) initial_disk: DiskObservation,
    volume_binding: Option<ObservedVolumeBinding>,
}

impl ResourceInventory {
    /// Creates production inventory from the host- and volume-bound observation.
    pub fn new_observed(
        environment: super::ObservedResourceEnvironment,
        operator: OperatorLimits,
        recovery_reserve: RecoveryReserve,
        cardinality: InventoryCardinalityLimits,
        disk_thresholds: DiskPressureThresholds,
    ) -> Result<Self, GovernorFailure> {
        let (detected, initial_disk, volume_binding) = environment.into_parts();
        Self::from_parts(
            detected,
            operator,
            recovery_reserve,
            cardinality,
            disk_thresholds,
            initial_disk,
            Some(volume_binding),
        )
    }

    /// Raw asserted inventory is confined to deterministic unit/fuzz sources.
    #[cfg(any(test, fuzzing))]
    pub fn new(
        detected: DetectedCapacity,
        operator: OperatorLimits,
        recovery_reserve: RecoveryReserve,
        cardinality: InventoryCardinalityLimits,
        disk_thresholds: DiskPressureThresholds,
        initial_disk: DiskObservation,
    ) -> Result<Self, GovernorFailure> {
        Self::from_parts(
            detected,
            operator,
            recovery_reserve,
            cardinality,
            disk_thresholds,
            initial_disk,
            None,
        )
    }

    fn from_parts(
        detected: DetectedCapacity,
        operator: OperatorLimits,
        recovery_reserve: RecoveryReserve,
        cardinality: InventoryCardinalityLimits,
        disk_thresholds: DiskPressureThresholds,
        initial_disk: DiskObservation,
        volume_binding: Option<ObservedVolumeBinding>,
    ) -> Result<Self, GovernorFailure> {
        let effective = detected.0.minimum(operator.0);
        require_capacity(effective)?;
        let ordinary = effective
            .checked_sub(recovery_reserve.0)
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        require_capacity(ordinary)?;
        let detected_disk = detected.0.get(ResourceDimension::DiskHeadroomBytes);
        if recovery_reserve.0.get(ResourceDimension::DiskHeadroomBytes) > disk_thresholds.hard_enter
            || disk_thresholds.soft_exit > detected_disk
            || initial_disk.usable_bytes > detected_disk
        {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            detected,
            operator,
            effective,
            recovery_reserve,
            cardinality,
            disk_thresholds,
            initial_disk,
            volume_binding,
        })
    }

    pub(super) fn take_volume_binding(&mut self) -> Option<ObservedVolumeBinding> {
        self.volume_binding.take()
    }
}

/// One trusted observation of currently usable disk bytes.
///
/// ```compile_fail
/// # use positron_kernel::DiskObservation;
/// let _ = DiskObservation::new(1);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskObservation {
    pub(super) usable_bytes: u64,
}

impl DiskObservation {
    #[must_use]
    #[cfg(any(test, fuzzing))]
    pub const fn new(usable_bytes: u64) -> Self {
        Self { usable_bytes }
    }

    pub(super) const fn from_observed(usable_bytes: u64) -> Self {
        Self { usable_bytes }
    }

    #[must_use]
    pub const fn usable_bytes(self) -> u64 {
        self.usable_bytes
    }
}

/// Absolute usable-byte pressure thresholds with hysteresis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskPressureThresholds {
    pub(super) hard_enter: u64,
    pub(super) hard_exit: u64,
    pub(super) soft_enter: u64,
    pub(super) soft_exit: u64,
}

impl DiskPressureThresholds {
    pub fn new(
        hard_enter: u64,
        hard_exit: u64,
        soft_enter: u64,
        soft_exit: u64,
    ) -> Result<Self, GovernorFailure> {
        if hard_enter >= hard_exit || hard_exit > soft_enter || soft_enter >= soft_exit {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            hard_enter,
            hard_exit,
            soft_enter,
            soft_exit,
        })
    }
}

/// Capacity withheld from ordinary admission for recovery-safe work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryReserve(ResourceAmounts);

impl RecoveryReserve {
    pub fn new(amounts: ResourceAmounts) -> Result<Self, GovernorFailure> {
        require_capacity(amounts).map(|()| Self(amounts))
    }

    pub(super) const fn amounts(self) -> ResourceAmounts {
        self.0
    }
}

/// One explicitly configured tenant ceiling beneath the global ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantQuota {
    pub(super) tenant: TenantId,
    pub(super) weight: u16,
    pub(super) limits: ResourceAmounts,
}

impl TenantQuota {
    pub fn new(
        tenant: TenantId,
        weight: u16,
        limits: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if weight == 0 {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        require_capacity(limits)?;
        Ok(Self {
            tenant,
            weight,
            limits,
        })
    }
}

fn require_capacity(amounts: ResourceAmounts) -> Result<(), GovernorFailure> {
    if amounts.all_positive()
        && ResourceDimension::ALL
            .iter()
            .all(|dimension| amounts.get(*dimension) > 0)
    {
        Ok(())
    } else {
        Err(GovernorFailure::InvalidConfiguration)
    }
}
