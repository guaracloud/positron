use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskPressureThresholds, GovernorPolicy,
    InstanceId, InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment,
    OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory, RetentionTimeAuthority,
    SegmentProtectionKey, SegmentScope, StorageKernelResourceAuthority, TenantQuota, WorkClaim,
    WorkKind,
};
use positron_signals::{
    SamplingDecision, ScanLimit, SpanKind, SpanObservation, TraceScan, TraceStore,
};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

#[test]
fn public_trace_store_seam_commits_and_reads_a_native_observation() -> Result<(), Box<dyn Error>> {
    let root = TestRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x81; 16])?,
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )?;
    let (retention, _) =
        RetentionTimeAuthority::establish_with_manual_elapsed(UnixNanoseconds::new(100));
    let tenant = TenantId::from_bytes([0x84; 16])?;
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(1)?);
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x85; 32])),
    )?;
    let observation = SpanObservation::checked_minimal(
        [0x86; 16],
        [0x87; 8],
        None,
        "public".to_owned(),
        Some(1),
        None,
        Vec::new(),
        SpanKind::Server,
        SamplingDecision::Unknown,
    )?;
    let empty_failure = TraceStore::new()
        .prepare(
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                positron_kernel::StoreBlockIdentity::new([0x89; 16])?,
            )?,
            Vec::new(),
        )
        .err()
        .ok_or("empty Trace Store preparation unexpectedly succeeded")?;
    assert_eq!(
        empty_failure.code(),
        positron_signals::TraceStoreFailureCode::InvalidInput
    );
    let too_many_failure = TraceStore::new()
        .prepare(
            ledger.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                positron_kernel::StoreBlockIdentity::new([0x8a; 16])?,
            )?,
            vec![observation.clone(); 1_025],
        )
        .err()
        .ok_or("oversized Trace Store preparation unexpectedly succeeded")?;
    assert_eq!(
        too_many_failure.code(),
        positron_signals::TraceStoreFailureCode::LimitExceeded
    );
    let logs_scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(2)?);
    let logs_ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention,
        &catalog,
        logs_scope,
        SegmentProtectionKey::from_owned(Box::new([0x8b; 32])),
    )?;
    let scope_failure = TraceStore::new()
        .prepare(
            logs_ledger.begin_store_block(
                preparation_capacity(&authority, tenant)?,
                positron_kernel::StoreBlockIdentity::new([0x8c; 16])?,
            )?,
            vec![observation.clone()],
        )
        .err()
        .ok_or("non-Trace preparation unexpectedly succeeded")?;
    assert_eq!(
        scope_failure.code(),
        positron_signals::TraceStoreFailureCode::PhysicalScopeMismatch
    );
    let prepared = TraceStore::new().prepare(
        ledger.begin_store_block(
            preparation_capacity(&authority, tenant)?,
            positron_kernel::StoreBlockIdentity::new([0x88; 16])?,
        )?,
        vec![observation.clone()],
    )?;
    ledger.append(prepared.into_store_block())?;
    let result = TraceStore::new().scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        TraceScan::all(ScanLimit::new(1)?),
    )?;
    assert_eq!(result.observations().len(), 1);
    assert_eq!(result.observations()[0].observation(), &observation);
    Ok(())
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "positron-trace-store-integration-{}-{}",
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

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

fn authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
    let observed = ObservedResourceEnvironment::observe(
        &volume,
        RegisteredResourceBounds::new([100, 100, 500_000_000, 500_000, 100, 100, 100])?,
    )?;
    let disk = observed.initial_disk().usable_bytes();
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = ResourceAmounts::new([2; 11]);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(
        add(add(durability, large)?, large)?,
        ResourceAmounts::new([12; 11]),
    )?;
    let ordinary = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(raw)?,
        RecoveryReserve::new(recovery_capacity)?,
        cardinality,
        DiskPressureThresholds::new(
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes),
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 1,
            recovery_capacity.get(ResourceDimension::DiskHeadroomBytes) + 2,
            disk,
        )?,
    )?;
    let tenant = TenantId::from_bytes([0x84; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary)?],
        OrdinaryPoolPolicy::new(
            ResourceAmounts::new([8; 11]),
            ResourceAmounts::new([6; 11]),
            ResourceAmounts::new([4; 11]),
            ResourceAmounts::new([2; 11]),
        )?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        ResourceGovernorConfiguration::new(inventory, policy, recovery)?,
    )?)
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
