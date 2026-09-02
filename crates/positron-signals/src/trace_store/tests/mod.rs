use super::{SamplingDecision, SpanKind, SpanObservation, StoredSpanObservation, codec};
use super::{TraceIncompleteness, TraceScan, TraceStore};
use crate::{
    ScanCancellation, ScanLimit, ScanObservationFailureCode, ScanObserver, TraceStoreFailureCode,
};
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
    CandidateKeyValue, ValueLimitProfile,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, GovernorPolicy,
    InstanceId, LifecycleClock, MountQualification, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPoolPolicy, OwnedPrimaryDataVolume, PrimaryDataVolume, RecoveryPoolCapacities,
    RecoveryReserve, RegisteredResourceBounds, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, RetentionTimeAuthority, SegmentProtectionKey,
    SegmentScope, StorageKernelResourceAuthority, TenantQuota, WorkClaim, WorkKind,
};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

mod codec_boundaries;
mod failures;
mod native;
mod physical;
mod resource_admission;
mod visibility;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-trace-store-test-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn replaced_byte(bytes: &[u8], offset: usize, value: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    *replaced
        .get_mut(offset)
        .ok_or("malformed fixture replacement offset")? = value;
    Ok(replaced)
}

fn replaced_bytes<const N: usize>(
    bytes: &[u8],
    offset: usize,
    values: [u8; N],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut replaced = bytes.to_vec();
    replaced
        .get_mut(offset..offset + values.len())
        .ok_or("malformed fixture replacement range")?
        .copy_from_slice(&values);
    Ok(replaced)
}

fn preparation_capacity(
    authority: &StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<positron_kernel::ResourceReservation<'_>, Box<dyn Error>> {
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?;
    Ok(authority
        .governor()
        .reserve(WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)?)?)
}

fn establish_kernel_authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = positron_kernel::InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
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
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        positron_kernel::DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary_capacity)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, recovery)?,
    )?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| -> Result<u64, Box<dyn Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| "resource capacity overflow".into())
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

struct AlwaysCancelled;

impl ScanCancellation for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct NeverObserved;

impl ScanObserver for NeverObserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

struct WorkBudgetExhausted;

impl ScanObserver for WorkBudgetExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}

struct BytesBudgetExhausted;

impl ScanObserver for BytesBudgetExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}

struct RecordsBudgetExhausted;

impl ScanObserver for RecordsBudgetExhausted {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_decoded_records(&self, _records: u64) -> Result<(), ScanObservationFailureCode> {
        Err(ScanObservationFailureCode::BudgetExhausted)
    }
}
