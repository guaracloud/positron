use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureThresholds, GovernorPolicy, InventoryCardinalityLimits, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PrimaryDataVolume,
    RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const DIMENSIONS: usize = 11;

pub struct TemporaryRoots {
    root: PathBuf,
}

pub fn temporary_roots() -> Result<TemporaryRoots, std::io::Error> {
    TemporaryRoots::new()
}

impl TemporaryRoots {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-ingest-auth-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("data"))?;
        fs::create_dir(root.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets")
    }
}

impl Drop for TemporaryRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub struct Fixture {
    pub authority: StorageKernelResourceAuthority,
    pub tenant: TenantId,
    _root: TemporaryKernelRoot,
}

pub fn fixture(tenant: TenantId) -> Result<Fixture, Box<dyn Error>> {
    let root = TemporaryKernelRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
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
    let ordinary_capacity = ResourceAmounts::new([
        8_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 800, 32, 2_000_000,
    ]);
    let governed = add(recovery_capacity, ordinary_capacity)?;
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
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, ordinary_capacity)?],
        OrdinaryPoolPolicy::new(uniform(8), uniform(6), uniform(4), uniform(2))?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
    let authority = StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|_| "kernel authority establishment failed")?;
    Ok(Fixture {
        authority,
        tenant,
        _root: root,
    })
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; DIMENSIONS])
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

struct TemporaryKernelRoot(PathBuf);

impl TemporaryKernelRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-ingest-kernel-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryKernelRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
