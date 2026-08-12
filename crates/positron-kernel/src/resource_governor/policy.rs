//! Conservative fixed ordinary-capacity partitions.

use super::bootstrap::{
    BootstrapAllocationStage, allocate_exact, into_boxed_exact, policy_payload_requirement,
};
use super::claim::WorkClass;
use super::failure::GovernorFailure;
use super::inventory::{MAX_TENANT_QUOTAS, TenantQuota};
use super::model::{ResourceAmounts, ResourceDimension};

/// Fixed ordinary-capacity pools exposed in bounded inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrdinaryPool {
    Shared,
    SecurityLifecycle,
    Ingest,
    InteractiveQueryTail,
    OrdinaryMaintenanceBackup,
}

impl OrdinaryPool {
    pub(super) const fn for_class(class: WorkClass) -> Option<Self> {
        match class {
            WorkClass::DurabilityRecovery => None,
            WorkClass::SecurityLifecycle => Some(Self::SecurityLifecycle),
            WorkClass::Ingest => Some(Self::Ingest),
            WorkClass::InteractiveQueryTail => Some(Self::InteractiveQueryTail),
            WorkClass::OrdinaryMaintenanceBackup => Some(Self::OrdinaryMaintenanceBackup),
        }
    }
}

/// Explicit protected class headroom. Every vector is positive across every
/// registered dimension, a conservative Release 1 cost that makes the stated
/// capacity guarantee meaningful without an applicability schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryPoolPolicy {
    security: ResourceAmounts,
    ingest: ResourceAmounts,
    query: ResourceAmounts,
    maintenance: ResourceAmounts,
}

impl OrdinaryPoolPolicy {
    pub fn new(
        security: ResourceAmounts,
        ingest: ResourceAmounts,
        query: ResourceAmounts,
        maintenance: ResourceAmounts,
    ) -> Result<Self, GovernorFailure> {
        if !security.all_positive()
            || !ingest.all_positive()
            || !query.all_positive()
            || !maintenance.all_positive()
        {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        let mut ingest_strict = false;
        for dimension in ResourceDimension::ALL {
            if security.get(dimension) < ingest.get(dimension)
                || ingest.get(dimension) < query.get(dimension)
            {
                return Err(GovernorFailure::InvalidConfiguration);
            }
            ingest_strict |= ingest.get(dimension) > query.get(dimension);
        }
        if !ingest_strict {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(Self {
            security,
            ingest,
            query,
            maintenance,
        })
    }

    pub(super) fn derive(
        self,
        ordinary: ResourceAmounts,
    ) -> Result<PoolCapacities, GovernorFailure> {
        let protected = self
            .security
            .checked_add(self.ingest)
            .and_then(|amounts| amounts.checked_add(self.query))
            .and_then(|amounts| amounts.checked_add(self.maintenance))
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        let shared = ordinary
            .checked_sub(protected)
            .ok_or(GovernorFailure::InvalidConfiguration)?;
        if !shared.all_positive() {
            return Err(GovernorFailure::InvalidConfiguration);
        }
        Ok(PoolCapacities {
            shared,
            security: self.security,
            ingest: self.ingest,
            query: self.query,
            maintenance: self.maintenance,
        })
    }
}

/// Bounded tenant policy and fixed class headroom.
#[derive(Debug)]
pub struct GovernorPolicy {
    pub(super) tenant_quotas: Box<[TenantQuota]>,
    pub(super) pools: OrdinaryPoolPolicy,
}

impl GovernorPolicy {
    pub fn new<const N: usize>(
        quotas: [TenantQuota; N],
        pools: OrdinaryPoolPolicy,
    ) -> Result<Self, GovernorFailure> {
        Self::new_with_failure(quotas, pools, None)
    }

    fn new_with_failure<const N: usize>(
        quotas: [TenantQuota; N],
        pools: OrdinaryPoolPolicy,
        fail_at: Option<BootstrapAllocationStage>,
    ) -> Result<Self, GovernorFailure> {
        if N == 0 || N > MAX_TENANT_QUOTAS {
            return Err(GovernorFailure::PolicyCardinalityExceeded);
        }
        for (index, quota) in quotas.iter().enumerate() {
            let remaining = index
                .checked_add(1)
                .ok_or(GovernorFailure::InvalidConfiguration)?;
            if quotas
                .iter()
                .skip(remaining)
                .any(|candidate| candidate.tenant == quota.tenant)
            {
                return Err(GovernorFailure::InvalidConfiguration);
            }
        }
        let required = policy_payload_requirement(N)?;
        let mut tenant_quotas = allocate_exact(
            N,
            required,
            BootstrapAllocationStage::PolicyTenantQuotas,
            fail_at,
        )?;
        tenant_quotas.extend(quotas);
        Ok(Self {
            tenant_quotas: into_boxed_exact(tenant_quotas, required)?,
            pools,
        })
    }

    #[cfg(test)]
    pub(super) fn new_failing_allocation<const N: usize>(
        quotas: [TenantQuota; N],
        pools: OrdinaryPoolPolicy,
    ) -> Result<Self, GovernorFailure> {
        Self::new_with_failure(
            quotas,
            pools,
            Some(BootstrapAllocationStage::PolicyTenantQuotas),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PoolCapacities {
    shared: ResourceAmounts,
    security: ResourceAmounts,
    ingest: ResourceAmounts,
    query: ResourceAmounts,
    maintenance: ResourceAmounts,
}

impl PoolCapacities {
    pub(super) const fn zero() -> Self {
        Self {
            shared: ResourceAmounts::zero(),
            security: ResourceAmounts::zero(),
            ingest: ResourceAmounts::zero(),
            query: ResourceAmounts::zero(),
            maintenance: ResourceAmounts::zero(),
        }
    }

    pub(super) const fn get(self, pool: OrdinaryPool) -> ResourceAmounts {
        match pool {
            OrdinaryPool::Shared => self.shared,
            OrdinaryPool::SecurityLifecycle => self.security,
            OrdinaryPool::Ingest => self.ingest,
            OrdinaryPool::InteractiveQueryTail => self.query,
            OrdinaryPool::OrdinaryMaintenanceBackup => self.maintenance,
        }
    }

    pub(super) fn with(self, pool: OrdinaryPool, amounts: ResourceAmounts) -> Self {
        let mut updated = self;
        match pool {
            OrdinaryPool::Shared => updated.shared = amounts,
            OrdinaryPool::SecurityLifecycle => updated.security = amounts,
            OrdinaryPool::Ingest => updated.ingest = amounts,
            OrdinaryPool::InteractiveQueryTail => updated.query = amounts,
            OrdinaryPool::OrdinaryMaintenanceBackup => updated.maintenance = amounts,
        }
        updated
    }

    pub(super) fn checked_add(self, other: Self) -> Option<Self> {
        let mut candidate = Self::zero();
        for pool in ORDINARY_POOLS {
            candidate = candidate.with(pool, self.get(pool).checked_add(other.get(pool))?);
        }
        Some(candidate)
    }

    pub(super) fn checked_sub(self, other: Self) -> Option<Self> {
        let mut candidate = Self::zero();
        for pool in ORDINARY_POOLS {
            candidate = candidate.with(pool, self.get(pool).checked_sub(other.get(pool))?);
        }
        Some(candidate)
    }

    pub(super) fn fair_share(self, weight: u16, total_weight: u64) -> Option<Self> {
        if weight == 0 || total_weight == 0 || u64::from(weight) > total_weight {
            return None;
        }
        let mut shares = Self::zero();
        for pool in ORDINARY_POOLS {
            let capacity = self.get(pool);
            let mut share = ResourceAmounts::zero();
            for dimension in ResourceDimension::ALL {
                share = share.with_amount(
                    dimension,
                    weighted_floor(capacity.get(dimension), weight, total_weight)?,
                );
            }
            shares = shares.with(pool, share);
        }
        Some(shares)
    }
}

pub(super) const ORDINARY_POOLS: [OrdinaryPool; 5] = [
    OrdinaryPool::Shared,
    OrdinaryPool::SecurityLifecycle,
    OrdinaryPool::Ingest,
    OrdinaryPool::InteractiveQueryTail,
    OrdinaryPool::OrdinaryMaintenanceBackup,
];

/// Exact two-pool breakdown for one ordinary reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PoolCharge {
    class_pool: OrdinaryPool,
    shared: ResourceAmounts,
    protected: ResourceAmounts,
}

impl PoolCharge {
    pub(super) const fn shared(self) -> ResourceAmounts {
        self.shared
    }
    pub(super) const fn new(
        class_pool: OrdinaryPool,
        shared: ResourceAmounts,
        protected: ResourceAmounts,
    ) -> Self {
        Self {
            class_pool,
            shared,
            protected,
        }
    }

    pub(super) fn capacities(self) -> PoolCapacities {
        PoolCapacities::zero()
            .with(OrdinaryPool::Shared, self.shared)
            .with(self.class_pool, self.protected)
    }

    pub(super) fn shrink_to(self, new: ResourceAmounts) -> Option<Self> {
        let mut shared = ResourceAmounts::zero();
        let mut protected = ResourceAmounts::zero();
        for dimension in ResourceDimension::ALL {
            let kept_shared = self.shared.get(dimension).min(new.get(dimension));
            let kept_protected = new.get(dimension).checked_sub(kept_shared)?;
            if kept_protected > self.protected.get(dimension) {
                return None;
            }
            shared = shared.with_amount(dimension, kept_shared);
            protected = protected.with_amount(dimension, kept_protected);
        }
        Some(Self::new(self.class_pool, shared, protected))
    }
}

/// Computes `floor(capacity * weight / total_weight)` without a `u64`
/// intermediate. The deliberately unavailable fractional residual preserves
/// deterministic, bounded tenant isolation.
pub(super) fn weighted_floor(capacity: u64, weight: u16, total_weight: u64) -> Option<u64> {
    let numerator = u128::from(capacity).checked_mul(u128::from(weight))?;
    let result = numerator.checked_div(u128::from(total_weight))?;
    u64::try_from(result).ok()
}
