use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::{PrincipalId, TenantId};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskPressureThresholds, GovernorPolicy,
    InstanceId, InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment,
    OperatorLimits, OrdinaryPoolPolicy, OwnedPrimaryDataVolume, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory, SegmentProtectionKey,
    SegmentScope, SnapshotLeaseId, SnapshotLeaseUsage, StorageKernelResourceAuthority, TenantQuota,
    WorkClaim, WorkKind,
};

use super::ExecutionResources;
use crate::QueryFailureCode;
use crate::cursor::CursorState;
use crate::{LogicalPlan, QueryBudget, QueryCancellation, TemporalAxis, TemporalRange};
use std::sync::Arc;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

#[test]
fn lease_identity_mismatch_releases_every_pre_stream_resource() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?),
        SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
    )?;
    let baseline = authority.governor().inspect()?;

    for iteration in 0..65 {
        let admission = authority.governor().reserve(WorkClaim::tenant(
            tenant,
            WorkKind::InteractiveQueryTail,
            ResourceAmounts::new([1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0]),
        )?)?;
        let lease = ledger.create_snapshot_lease(100 + iteration, 200 + iteration)?;
        let identity = lease.identity();
        drop(lease);
        let resources = ExecutionResources::new(admission, identity, SnapshotLeaseUsage::default());
        let expected = SnapshotLeaseId::new([0x99; 16])?;

        let state = test_cursor_state(identity.to_bytes());
        let failure = match resources.validate_lease_identity(&ledger, &state, expected.to_bytes())
        {
            Ok(_) => return Err("mismatched stream identity was accepted".into()),
            Err(failure) => failure,
        };
        assert_eq!(failure.code(), QueryFailureCode::Internal);
        assert_eq!(
            ledger
                .resume_snapshot_lease(identity, 100 + iteration)
                .expect_err("mismatched lease is released")
                .code(),
            positron_kernel::LedgerFailureCode::SnapshotExpired
        );
        let after = authority.governor().inspect()?;
        assert_eq!(after.outstanding_total(), baseline.outstanding_total());
        for dimension in ResourceDimension::ALL {
            assert_eq!(after.usage(dimension), baseline.usage(dimension));
        }
    }
    Ok(())
}

#[test]
fn failed_usage_reconciliation_retains_the_durable_lease_for_retry() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x41; 16])?,
        CatalogSecret::from_owned(Box::new([0x42; 32]), Box::new([0x43; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(1)?),
        SegmentProtectionKey::from_owned(Box::new([0x44; 32])),
    )?;
    let admission = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::new([1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0]),
    )?)?;
    let lease = ledger.create_snapshot_lease(100, 200)?;
    let identity = lease.identity();
    let usage = SnapshotLeaseUsage::new(1, 0, 0, 0, 0, 0, 0);
    assert_eq!(ledger.record_snapshot_lease_usage(identity, usage)?, usage);
    let resources = ExecutionResources::new(admission, identity, usage);
    let state = test_cursor_state(identity.to_bytes());

    let failure = resources.fail_before_stream(
        &ledger,
        &state,
        crate::QueryFailure::new(QueryFailureCode::Internal),
    );
    assert_eq!(failure.code(), QueryFailureCode::Internal);
    assert_eq!(ledger.snapshot_lease_usage(identity, 100)?, usage);
    ledger.release_snapshot_lease(identity)?;
    Ok(())
}

fn test_cursor_state(lease_identity: [u8; 16]) -> CursorState {
    CursorState {
        principal: PrincipalId::from_bytes([0x35; 16]).expect("non-zero principal"),
        tenant: TenantId::from_bytes([0x64; 16]).expect("non-zero tenant"),
        authorization_generation: 1,
        catalog_identity: [0x36; 32],
        catalog_generation: 1,
        frontier: 1,
        plan: Arc::new(LogicalPlan::logs(
            TemporalAxis::QueryTime,
            TemporalRange::new(-1, 1).expect("ordered range"),
            1,
        )),
        source: None,
        language: None,
        plan_digest: [0; 32],
        resume_key: None,
        sequence: 0,
        prior_digest: [0; 32],
        lease_identity,
        expiry: 200,
        budget: QueryBudget::new(100, 10, 10, 100, 1_000, 100).expect("valid budget"),
        scanned_bytes: 0,
        decoded_records: 0,
        physical_scanned_bytes: 0,
        physical_decoded_records: 0,
        output_rows: 0,
        output_bytes: 0,
        physical_output_rows: 0,
        physical_output_bytes: 0,
        memory_peak_bytes: 0,
        physical_memory_peak_bytes: 0,
        started_at: 100,
        last_observed_at: 100,
        cpu_work_units: 0,
        elapsed_wall_seconds: 0,
        physical_cpu_work_units: 0,
        physical_elapsed_wall_seconds: 0,
        reduced_pruning: false,
        resume_count: 0,
        repeated_batch_count: 0,
        cancellation: QueryCancellation::new(),
    }
}

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-query-resource-test-{}-{sequence}",
            std::process::id()
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

fn establish_authority(
    volume: OwnedPrimaryDataVolume,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 16)?;
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
    let tenant_capacity = ResourceAmounts::new([
        5_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, tenant_capacity)?;
    let raw = add(governed, cardinality.governor_bootstrap_overhead(1)?)?;
    let disk = observed.initial_disk().usable_bytes();
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
    let tenant = TenantId::from_bytes([0x64; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, tenant_capacity)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
    Ok(StorageKernelResourceAuthority::establish(
        volume,
        configuration,
    )?)
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn add(left: ResourceAmounts, right: ResourceAmounts) -> Result<ResourceAmounts, Box<dyn Error>> {
    let value = |dimension| -> Result<u64, Box<dyn Error>> {
        left.get(dimension)
            .checked_add(right.get(dimension))
            .ok_or_else(|| "query resource test capacity overflow".into())
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
