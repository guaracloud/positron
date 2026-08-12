//! Validated governor topology derivation and zero-state construction.

use super::*;
use crate::resource_governor::bootstrap::{allocate_exact, into_boxed_exact};

impl GovernorInner {
    pub(in crate::resource_governor) fn configure(
        input: GovernorSetupInput,
    ) -> Result<GovernorConfiguration, GovernorFailure> {
        let GovernorSetupInput {
            raw_effective,
            bootstrap_overhead,
            total_ceiling,
            ordinary_ceiling,
            tenant_quotas,
            maximum_outstanding,
            pool_capacities,
            recovery_pool_capacities,
            disk_thresholds,
            initial_disk,
            layout,
            fail_at,
        } = input;
        let required = layout.overhead();
        let tenant_count = layout.tenant_count();
        let total_weight = total_weight(&tenant_quotas)?;

        let ordinary_fair = allocate_exact(
            tenant_count,
            required,
            BootstrapAllocationStage::OrdinaryTenantFairCapacities,
            fail_at,
        )?;
        let tenant_fair_capacities =
            ordinary_capacities(&tenant_quotas, pool_capacities, total_weight, ordinary_fair)?;

        let protected_sum = recovery_pool_capacities
            .protected_sum()
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        let recovery_shared_capacity = total_ceiling
            .checked_sub(protected_sum)
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        let recovery_shared_fair = allocate_exact(
            tenant_count,
            required,
            BootstrapAllocationStage::RecoveryTenantSharedFair,
            fail_at,
        )?;
        let recovery_tenant_shared_fair = amount_capacities(
            &tenant_quotas,
            recovery_shared_capacity,
            total_weight,
            recovery_shared_fair,
        )?;

        validate_system_recovery_progress(&tenant_quotas, recovery_pool_capacities)?;
        let recovery_pool_fair = allocate_exact(
            tenant_count,
            required,
            BootstrapAllocationStage::RecoveryTenantPoolFair,
            fail_at,
        )?;
        let recovery_tenant_pool_fair = recovery_fair_capacities(
            &tenant_quotas,
            recovery_pool_capacities,
            total_weight,
            recovery_pool_fair,
        )?;
        let recovery_system_pool_capacities =
            system_recovery_capacities(recovery_pool_capacities, &recovery_tenant_pool_fair)?;
        validate_progress(&tenant_quotas, &tenant_fair_capacities, maximum_outstanding)?;
        let recovery_reserve = total_ceiling
            .checked_sub(ordinary_ceiling)
            .ok_or(GovernorFailure::InvalidConfiguration)?;

        let ordinary_tenant_usage = zeroed_tenant_table(
            layout,
            required,
            BootstrapAllocationStage::OrdinaryTenantUsage,
            fail_at,
            ResourceAmounts::zero(),
        )?;
        let recovery_tenant_usage = zeroed_tenant_table(
            layout,
            required,
            BootstrapAllocationStage::RecoveryTenantUsage,
            fail_at,
            ResourceAmounts::zero(),
        )?;
        let recovery_tenant_pool_usage = zeroed_tenant_table(
            layout,
            required,
            BootstrapAllocationStage::RecoveryTenantPoolUsage,
            fail_at,
            RecoveryPoolUsage::zero(),
        )?;
        let ordinary_tenant_pool_usage = zeroed_tenant_table(
            layout,
            required,
            BootstrapAllocationStage::OrdinaryTenantPoolUsage,
            fail_at,
            PoolCapacities::zero(),
        )?;
        let tenant_outstanding = zeroed_tenant_table(
            layout,
            required,
            BootstrapAllocationStage::TenantOutstanding,
            fail_at,
            0_u32,
        )?;

        let ledger = super::super::ledger::allocate(layout, required, fail_at)?;
        let super::super::ledger::LedgerAllocation {
            signals,
            pending_words,
            records,
            free_slots,
        } = ledger;
        let initial_pressure = disk_thresholds.initial(initial_disk);
        let state = AccountingState {
            rejection_counts: [0; AdmissionFailureCode::COUNT],
            grant_records: records,
            free_slots,
            total_usage: ResourceAmounts::zero(),
            recovery_usage: ResourceAmounts::zero(),
            ordinary_tenant_usage,
            recovery_tenant_usage,
            recovery_pool_usage: RecoveryPoolUsage::zero(),
            recovery_system_pool_usage: RecoveryPoolUsage::zero(),
            recovery_tenant_pool_usage,
            pool_usage: PoolCapacities::zero(),
            ordinary_tenant_pool_usage,
            tenant_outstanding,
            outstanding: 0,
            disk_pressure: initial_pressure,
            usable_disk_bytes: initial_disk.usable_bytes,
            pressure_transition_count: 0,
            lifecycle: GovernorLifecycle::Open,
            outstanding_ordinary: 0,
            outstanding_recovery: 0,
            outstanding_uninterruptible: 0,
            class_counts: empty_class_counts(),
        };

        Ok(GovernorConfiguration {
            raw_effective,
            bootstrap_overhead,
            total_ceiling,
            ordinary_ceiling,
            recovery_reserve,
            tenant_quotas,
            maximum_outstanding,
            pool_capacities,
            tenant_fair_capacities: into_boxed_exact(tenant_fair_capacities, required)?,
            recovery_pool_capacities,
            recovery_shared_capacity,
            recovery_tenant_shared_fair: into_boxed_exact(recovery_tenant_shared_fair, required)?,
            recovery_tenant_pool_fair: into_boxed_exact(recovery_tenant_pool_fair, required)?,
            recovery_system_pool_capacities,
            disk_thresholds,
            state,
            slot_signals: signals,
            pending_words,
        })
    }

    /// Moves a fully allocated configuration into inline state. `Mutex::new`
    /// and atomic construction retain their values inline and do not allocate.
    pub(in crate::resource_governor) fn new(
        ownership: KernelOwnership,
        configuration: GovernorConfiguration,
    ) -> Self {
        let initial_pressure = configuration.state.disk_pressure;
        Self {
            ownership,
            raw_effective: configuration.raw_effective,
            bootstrap_overhead: configuration.bootstrap_overhead,
            total_ceiling: configuration.total_ceiling,
            ordinary_ceiling: configuration.ordinary_ceiling,
            recovery_reserve: configuration.recovery_reserve,
            tenant_quotas: configuration.tenant_quotas,
            maximum_outstanding: configuration.maximum_outstanding,
            pool_capacities: configuration.pool_capacities,
            tenant_fair_capacities: configuration.tenant_fair_capacities,
            recovery_pool_capacities: configuration.recovery_pool_capacities,
            recovery_shared_capacity: configuration.recovery_shared_capacity,
            recovery_tenant_shared_fair: configuration.recovery_tenant_shared_fair,
            recovery_tenant_pool_fair: configuration.recovery_tenant_pool_fair,
            recovery_system_pool_capacities: configuration.recovery_system_pool_capacities,
            disk_thresholds: configuration.disk_thresholds,
            state: Mutex::new(configuration.state),
            slot_signals: configuration.slot_signals,
            pending_words: configuration.pending_words,
            has_pending_releases: AtomicBool::new(false),
            last_pressure: AtomicU8::new(pressure_index(initial_pressure)),
            pending_fence: AtomicBool::new(false),
            contention_count: AtomicU64::new(0),
        }
    }
}

fn zeroed_tenant_table<T: Copy>(
    layout: BootstrapInventoryLayout,
    required: ResourceAmounts,
    stage: BootstrapAllocationStage,
    fail_at: Option<BootstrapAllocationStage>,
    value: T,
) -> Result<Box<[T]>, GovernorFailure> {
    let mut allocation = allocate_exact(layout.tenant_count(), required, stage, fail_at)?;
    allocation.resize(layout.tenant_count(), value);
    into_boxed_exact(allocation, required)
}
