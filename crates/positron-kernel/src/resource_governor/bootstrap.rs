//! Canonical logical inventory and exact-capacity bootstrap allocations.

use std::mem::size_of;
use std::sync::atomic::{AtomicU8, AtomicU64};

use super::StorageKernelResourceAuthority;
#[cfg(test)]
use super::accounting::AccountingState;
use super::failure::GovernorFailure;
use super::inventory::TenantQuota;
use super::ledger::GrantRecord;
use super::model::{ResourceAmounts, ResourceDimension};
use super::policy::PoolCapacities;
use super::recovery_policy::{RecoveryPoolCapacities, RecoveryPoolUsage};

pub(super) const RETAINED_PRIMARY_DATA_VOLUME_FILE_DESCRIPTORS: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootstrapAllocationStage {
    PolicyTenantQuotas,
    OrdinaryTenantFairCapacities,
    RecoveryTenantSharedFair,
    RecoveryTenantPoolFair,
    OrdinaryTenantUsage,
    RecoveryTenantUsage,
    RecoveryTenantPoolUsage,
    OrdinaryTenantPoolUsage,
    TenantOutstanding,
    LedgerSignals,
    LedgerPendingWords,
    LedgerRecords,
    LedgerFreeSlots,
}

#[cfg(test)]
pub(super) const CONFIGURATION_ALLOCATION_STAGES: [BootstrapAllocationStage; 12] = [
    BootstrapAllocationStage::OrdinaryTenantFairCapacities,
    BootstrapAllocationStage::RecoveryTenantSharedFair,
    BootstrapAllocationStage::RecoveryTenantPoolFair,
    BootstrapAllocationStage::OrdinaryTenantUsage,
    BootstrapAllocationStage::RecoveryTenantUsage,
    BootstrapAllocationStage::RecoveryTenantPoolUsage,
    BootstrapAllocationStage::OrdinaryTenantPoolUsage,
    BootstrapAllocationStage::TenantOutstanding,
    BootstrapAllocationStage::LedgerSignals,
    BootstrapAllocationStage::LedgerPendingWords,
    BootstrapAllocationStage::LedgerRecords,
    BootstrapAllocationStage::LedgerFreeSlots,
];

/// One checked authority for retained logical payload and fixed root bytes.
///
/// Allocator metadata and platform allocation rounding are deliberately not
/// claimed. Every payload vector has exactly the requested capacity before it
/// is filled; the fixed root size counts its Box/Vec headers once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BootstrapInventoryLayout {
    tenant_count: usize,
    outstanding_count: usize,
    pending_word_count: usize,
    memory_bytes: u64,
}

impl BootstrapInventoryLayout {
    pub(super) fn new(
        tenant_count: usize,
        maximum_outstanding: u32,
    ) -> Result<Self, GovernorFailure> {
        if tenant_count == 0 {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        let outstanding_count = usize::try_from(maximum_outstanding)
            .map_err(|_| GovernorFailure::InvalidConfiguration)?;
        if outstanding_count == 0 {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        let pending_word_count = outstanding_count
            .checked_add(63)
            .and_then(|count| count.checked_div(64))
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        let fixed = size_of::<StorageKernelResourceAuthority>();
        let tenant_payload = tenant_payload_bytes(tenant_count)?;
        let ledger_payload = ledger_payload_bytes(outstanding_count, pending_word_count)?;
        let memory_bytes = fixed
            .checked_add(tenant_payload)
            .and_then(|bytes| bytes.checked_add(ledger_payload))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        Ok(Self {
            tenant_count,
            outstanding_count,
            pending_word_count,
            memory_bytes,
        })
    }

    pub(super) const fn tenant_count(self) -> usize {
        self.tenant_count
    }

    pub(super) const fn outstanding_count(self) -> usize {
        self.outstanding_count
    }

    pub(super) const fn pending_word_count(self) -> usize {
        self.pending_word_count
    }

    pub(super) fn overhead(self) -> ResourceAmounts {
        ResourceAmounts::zero()
            .with_amount(ResourceDimension::MemoryBytes, self.memory_bytes)
            .with_amount(
                ResourceDimension::FileDescriptors,
                RETAINED_PRIMARY_DATA_VOLUME_FILE_DESCRIPTORS,
            )
    }

    #[cfg(test)]
    pub(super) const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }
}

pub(super) fn policy_payload_requirement(
    tenant_count: usize,
) -> Result<ResourceAmounts, GovernorFailure> {
    let bytes = payload_bytes::<TenantQuota>(tenant_count)?;
    let memory = u64::try_from(bytes).map_err(|_| GovernorFailure::InvalidConfiguration)?;
    Ok(ResourceAmounts::zero().with_amount(ResourceDimension::MemoryBytes, memory))
}

pub(super) fn allocate_exact<T>(
    count: usize,
    required: ResourceAmounts,
    stage: BootstrapAllocationStage,
    fail_at: Option<BootstrapAllocationStage>,
) -> Result<Vec<T>, GovernorFailure> {
    if size_of::<T>() == 0 {
        return Err(GovernorFailure::InvalidConfiguration);
    }
    if fail_at == Some(stage) {
        return Err(GovernorFailure::GovernorBootstrapInventoryUnavailable { required });
    }
    let mut allocation = Vec::new();
    allocation
        .try_reserve_exact(count)
        .map_err(|_| GovernorFailure::GovernorBootstrapInventoryUnavailable { required })?;
    if allocation.capacity() != count {
        return Err(GovernorFailure::GovernorBootstrapInventoryUnavailable { required });
    }
    Ok(allocation)
}

pub(super) fn into_boxed_exact<T>(
    allocation: Vec<T>,
    required: ResourceAmounts,
) -> Result<Box<[T]>, GovernorFailure> {
    if allocation.len() != allocation.capacity() {
        return Err(GovernorFailure::GovernorBootstrapInventoryUnavailable { required });
    }
    Ok(allocation.into_boxed_slice())
}

fn tenant_payload_bytes(tenant_count: usize) -> Result<usize, GovernorFailure> {
    [
        payload_bytes::<TenantQuota>(tenant_count)?,
        payload_bytes::<PoolCapacities>(tenant_count)?,
        payload_bytes::<ResourceAmounts>(tenant_count)?,
        payload_bytes::<RecoveryPoolCapacities>(tenant_count)?,
        payload_bytes::<ResourceAmounts>(tenant_count)?,
        payload_bytes::<ResourceAmounts>(tenant_count)?,
        payload_bytes::<RecoveryPoolUsage>(tenant_count)?,
        payload_bytes::<PoolCapacities>(tenant_count)?,
        payload_bytes::<u32>(tenant_count)?,
    ]
    .into_iter()
    .try_fold(0_usize, |total, bytes| total.checked_add(bytes))
    .ok_or(GovernorFailure::InvalidConfiguration)
}

fn ledger_payload_bytes(
    outstanding_count: usize,
    pending_word_count: usize,
) -> Result<usize, GovernorFailure> {
    [
        payload_bytes::<AtomicU8>(outstanding_count)?,
        payload_bytes::<AtomicU64>(pending_word_count)?,
        payload_bytes::<Option<GrantRecord>>(outstanding_count)?,
        payload_bytes::<u16>(outstanding_count)?,
    ]
    .into_iter()
    .try_fold(0_usize, |total, bytes| total.checked_add(bytes))
    .ok_or(GovernorFailure::InvalidConfiguration)
}

fn payload_bytes<T>(count: usize) -> Result<usize, GovernorFailure> {
    let element = size_of::<T>();
    if element == 0 {
        return Err(GovernorFailure::InvalidConfiguration);
    }
    count
        .checked_mul(element)
        .ok_or(GovernorFailure::InvalidConfiguration)
}

#[cfg(test)]
pub(super) fn fixed_root_bytes_for_test() -> usize {
    size_of::<StorageKernelResourceAuthority>()
}

#[cfg(test)]
pub(super) fn fixed_accounting_state_bytes_for_test() -> usize {
    size_of::<AccountingState>()
}

#[cfg(test)]
#[path = "tests/bootstrap.rs"]
mod tests;
