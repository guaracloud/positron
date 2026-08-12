//! Fixed-cardinality governor observations.

use super::accounting;
use super::failure::{AdmissionFailureCode, DiskPressureState};
use super::lifecycle::GovernorLifecycle;
use super::model::{ResourceAmounts, ResourceDimension};
use super::policy::{OrdinaryPool, PoolCapacities};
use super::{RecoveryPoolCapacities, RecoveryWorkKind, WorkClass};

/// Fixed-cardinality governor inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceSnapshot {
    outstanding_reservations: u32,
    maximum_outstanding_reservations: u32,
    reserve_consumption: ResourceAmounts,
    pool_capacities: PoolCapacities,
    pool_usage: PoolCapacities,
    disk_pressure: DiskPressureState,
    pressure_transition_count: u64,
    lifecycle: GovernorLifecycle,
    total_usage: ResourceAmounts,
    outstanding_ordinary: u32,
    outstanding_recovery: u32,
    outstanding_uninterruptible: u32,
    class_counts: [u32; 5],
    rejection_count: u64,
    rejection_counts: [u64; AdmissionFailureCode::COUNT],
    throttle_counts: [u64; AdmissionFailureCode::COUNT],
    effective_capacity: ResourceAmounts,
    bootstrap_overhead: ResourceAmounts,
    ordinary_capacity: ResourceAmounts,
    recovery_reserve: ResourceAmounts,
    recovery_shared_capacity: ResourceAmounts,
    recovery_shared_usage: ResourceAmounts,
    recovery_pool_capacities: RecoveryPoolCapacities,
    recovery_pool_usage: super::recovery_policy::RecoveryPoolUsage,
    usable_disk_bytes: u64,
}

impl ResourceSnapshot {
    #[must_use]
    pub const fn outstanding_reservations(self) -> u32 {
        self.outstanding_reservations
    }
    #[must_use]
    pub const fn maximum_outstanding_reservations(self) -> u32 {
        self.maximum_outstanding_reservations
    }
    #[must_use]
    pub const fn reserve_consumption(self, dimension: ResourceDimension) -> u64 {
        self.reserve_consumption.get(dimension)
    }
    #[must_use]
    pub const fn pool_capacity(self, pool: OrdinaryPool, dimension: ResourceDimension) -> u64 {
        self.pool_capacities.get(pool).get(dimension)
    }
    #[must_use]
    pub const fn pool_usage(self, pool: OrdinaryPool, dimension: ResourceDimension) -> u64 {
        self.pool_usage.get(pool).get(dimension)
    }
    #[must_use]
    pub const fn disk_pressure(self) -> DiskPressureState {
        self.disk_pressure
    }
    #[must_use]
    pub const fn pressure_transition_count(self) -> u64 {
        self.pressure_transition_count
    }
    #[must_use]
    pub const fn lifecycle(self) -> GovernorLifecycle {
        self.lifecycle
    }
    #[must_use]
    pub const fn outstanding_total(self) -> u32 {
        self.outstanding_reservations
    }
    #[must_use]
    pub const fn outstanding_ordinary(self) -> u32 {
        self.outstanding_ordinary
    }
    #[must_use]
    pub const fn outstanding_recovery(self) -> u32 {
        self.outstanding_recovery
    }
    #[must_use]
    pub const fn outstanding_uninterruptible(self) -> u32 {
        self.outstanding_uninterruptible
    }
    #[must_use]
    pub const fn outstanding_for(self, class: WorkClass) -> u32 {
        let [recovery, security, ingest, query, maintenance] = self.class_counts;
        match class {
            WorkClass::DurabilityRecovery => recovery,
            WorkClass::SecurityLifecycle => security,
            WorkClass::Ingest => ingest,
            WorkClass::InteractiveQueryTail => query,
            WorkClass::OrdinaryMaintenanceBackup => maintenance,
        }
    }
    #[must_use]
    pub const fn rejection_count(self) -> u64 {
        self.rejection_count
    }
    #[must_use]
    pub const fn rejection_count_for(self, reason: AdmissionFailureCode) -> u64 {
        observation_for(self.rejection_counts, reason)
    }
    #[must_use]
    pub const fn throttle_count_for(self, reason: AdmissionFailureCode) -> u64 {
        observation_for(self.throttle_counts, reason)
    }
    #[must_use]
    pub const fn effective_capacity(self, dimension: ResourceDimension) -> u64 {
        self.effective_capacity.get(dimension)
    }
    /// Fixed Storage Kernel memory retained by the preallocated governor ledger.
    #[must_use]
    pub const fn governor_bootstrap_overhead(self, dimension: ResourceDimension) -> u64 {
        self.bootstrap_overhead.get(dimension)
    }
    #[must_use]
    pub const fn ordinary_capacity(self, dimension: ResourceDimension) -> u64 {
        self.ordinary_capacity.get(dimension)
    }
    #[must_use]
    pub const fn recovery_reserve_capacity(self, dimension: ResourceDimension) -> u64 {
        self.recovery_reserve.get(dimension)
    }
    /// Capacity available to any valid recovery kind before protected pools.
    #[must_use]
    pub const fn recovery_shared_capacity(self, dimension: ResourceDimension) -> u64 {
        self.recovery_shared_capacity.get(dimension)
    }
    /// Current shared recovery charge across every recovery kind.
    #[must_use]
    pub const fn recovery_shared_usage(self, dimension: ResourceDimension) -> u64 {
        self.recovery_shared_usage.get(dimension)
    }
    /// Protected capacity assigned to one closed recovery kind.
    #[must_use]
    pub const fn recovery_pool_capacity(
        self,
        kind: RecoveryWorkKind,
        dimension: ResourceDimension,
    ) -> u64 {
        self.recovery_pool_capacities.get(kind).get(dimension)
    }
    /// Current protected charge assigned to one closed recovery kind.
    #[must_use]
    pub fn recovery_pool_usage(self, kind: RecoveryWorkKind, dimension: ResourceDimension) -> u64 {
        self.recovery_pool_usage.protected(kind).get(dimension)
    }
    #[must_use]
    pub const fn usable_disk_bytes(self) -> u64 {
        self.usable_disk_bytes
    }
    #[must_use]
    pub const fn usage(self, dimension: ResourceDimension) -> u64 {
        self.total_usage.get(dimension)
    }
    #[must_use]
    pub const fn complete(self) -> bool {
        self.outstanding_reservations == 0
    }

    pub(super) fn from_accounting(snapshot: accounting::AccountingSnapshot) -> Self {
        Self {
            outstanding_reservations: snapshot.outstanding,
            maximum_outstanding_reservations: snapshot.maximum_outstanding,
            reserve_consumption: snapshot.reserve_consumption,
            pool_capacities: snapshot.pool_capacities,
            pool_usage: snapshot.pool_usage,
            disk_pressure: snapshot.disk_pressure,
            pressure_transition_count: snapshot.pressure_transition_count,
            lifecycle: snapshot.lifecycle,
            total_usage: snapshot.total_usage,
            outstanding_ordinary: snapshot.outstanding_ordinary,
            outstanding_recovery: snapshot.outstanding_recovery,
            outstanding_uninterruptible: snapshot.outstanding_uninterruptible,
            class_counts: snapshot.class_counts,
            rejection_count: snapshot.rejection_count,
            rejection_counts: snapshot.rejection_counts,
            throttle_counts: snapshot.throttle_counts,
            effective_capacity: snapshot.effective_capacity,
            bootstrap_overhead: snapshot.bootstrap_overhead,
            ordinary_capacity: snapshot.ordinary_capacity,
            recovery_reserve: snapshot.recovery_reserve,
            recovery_shared_capacity: snapshot.recovery_shared_capacity,
            recovery_shared_usage: snapshot.recovery_shared_usage,
            recovery_pool_capacities: snapshot.recovery_pool_capacities,
            recovery_pool_usage: snapshot.recovery_pool_usage,
            usable_disk_bytes: snapshot.usable_disk_bytes,
        }
    }
}

const fn observation_for(
    counts: [u64; AdmissionFailureCode::COUNT],
    reason: AdmissionFailureCode,
) -> u64 {
    let [
        capacity,
        quota,
        unregistered,
        outstanding,
        protected,
        class,
        fair,
        recovery_occupied,
        pressure,
        reserve,
        shutdown,
        internal,
        contended,
    ] = counts;
    match reason {
        AdmissionFailureCode::CapacityExhausted => capacity,
        AdmissionFailureCode::TenantQuotaExceeded => quota,
        AdmissionFailureCode::UnregisteredTenant => unregistered,
        AdmissionFailureCode::OutstandingReservationLimit => outstanding,
        AdmissionFailureCode::ProtectedCapacityUnavailable => protected,
        AdmissionFailureCode::ClassCapacityUnavailable => class,
        AdmissionFailureCode::TenantFairShareExceeded => fair,
        AdmissionFailureCode::CapacityOccupiedByRecovery => recovery_occupied,
        AdmissionFailureCode::DiskPressureAdmissionRefused => pressure,
        AdmissionFailureCode::RecoveryReserveExhausted => reserve,
        AdmissionFailureCode::ShuttingDown => shutdown,
        AdmissionFailureCode::InternalFenced => internal,
        AdmissionFailureCode::GovernorContended => contended,
    }
}
