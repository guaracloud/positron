use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureState, DiskPressureThresholds, GovernorFailure, GovernorPolicy,
    InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPoolPolicy, PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve,
    RegisteredResourceBounds, ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration,
    ResourceInventory, StorageKernelResourceAuthority, TenantQuota,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-resource-observation-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

fn observed_amounts(observed: &ObservedResourceEnvironment) -> ResourceAmounts {
    let detected = observed.detected_capacity();
    ResourceAmounts::new([
        detected.amount(ResourceDimension::MemoryBytes),
        detected.amount(ResourceDimension::QueueSlots),
        detected.amount(ResourceDimension::TaskSlots),
        detected.amount(ResourceDimension::BufferCacheBytes),
        detected.amount(ResourceDimension::BatchItems),
        detected.amount(ResourceDimension::LeaseSlots),
        detected.amount(ResourceDimension::RetrySlots),
        detected.amount(ResourceDimension::IoPermits),
        detected.amount(ResourceDimension::CpuWorkUnits),
        detected.amount(ResourceDimension::FileDescriptors),
        detected.amount(ResourceDimension::DiskHeadroomBytes),
    ])
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove resource-observation root: {error}");
        }
    }
}

#[test]
fn production_observation_binds_host_capacity_and_initial_disk_to_the_owned_volume()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let registered = RegisteredResourceBounds::new([11, 12, 13, 14, 15, 16, 17])?;

    let observed = ObservedResourceEnvironment::observe(&volume, registered)?;
    let detected = observed.detected_capacity();

    assert!(detected.amount(ResourceDimension::MemoryBytes) > 0);
    assert_eq!(detected.amount(ResourceDimension::QueueSlots), 11);
    assert_eq!(detected.amount(ResourceDimension::TaskSlots), 12);
    assert_eq!(detected.amount(ResourceDimension::BufferCacheBytes), 13);
    assert_eq!(detected.amount(ResourceDimension::BatchItems), 14);
    assert_eq!(detected.amount(ResourceDimension::LeaseSlots), 15);
    assert_eq!(detected.amount(ResourceDimension::RetrySlots), 16);
    assert_eq!(detected.amount(ResourceDimension::IoPermits), 17);
    assert!(detected.amount(ResourceDimension::CpuWorkUnits) > 0);
    assert!(detected.amount(ResourceDimension::FileDescriptors) > 2);
    assert_eq!(
        detected.amount(ResourceDimension::DiskHeadroomBytes),
        observed.initial_disk().usable_bytes()
    );
    assert!(observed.initial_disk().usable_bytes() > 0);
    Ok(())
}

#[test]
fn production_inventory_and_ongoing_disk_observation_retain_the_same_volume_authority()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let observed =
        ObservedResourceEnvironment::observe(&volume, RegisteredResourceBounds::new([1_000; 7])?)?;
    let detected = observed_amounts(&observed);
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(detected)?,
        RecoveryReserve::new(uniform(20))?,
        InventoryCardinalityLimits::new(1, 16)?,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )?;
    let tenant = TenantId::from_bytes([91; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(1))?],
        OrdinaryPoolPolicy::new(uniform(4), uniform(3), uniform(2), uniform(1))?,
    )?;
    let one = uniform(1);
    let two = uniform(2);
    let recovery = RecoveryPoolCapacities::new(two, one, two, one, two, one, one)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
    let authority = StorageKernelResourceAuthority::establish(volume, configuration)?;

    assert_eq!(authority.observe_disk()?, DiskPressureState::Healthy);
    assert!(authority.governor().inspect()?.usable_disk_bytes() > 0);
    Ok(())
}

#[test]
fn establishment_rejects_a_different_volume_and_returns_both_capabilities()
-> Result<(), Box<dyn Error>> {
    let observed_root = TemporaryRoot::new()?;
    let substitute_root = TemporaryRoot::new()?;
    let observed_volume =
        PrimaryDataVolume::acquire(&observed_root.0, MountQualification::LocalHost)?;
    let substitute_volume =
        PrimaryDataVolume::acquire(&substitute_root.0, MountQualification::LocalHost)?;
    let observed = ObservedResourceEnvironment::observe(
        &observed_volume,
        RegisteredResourceBounds::new([1_000; 7])?,
    )?;
    let detected = observed_amounts(&observed);
    let disk = observed.initial_disk().usable_bytes();
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(detected)?,
        RecoveryReserve::new(uniform(20))?,
        InventoryCardinalityLimits::new(1, 16)?,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )?;
    let tenant = TenantId::from_bytes([92; 16])?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(1))?],
        OrdinaryPoolPolicy::new(uniform(4), uniform(3), uniform(2), uniform(1))?,
    )?;
    let one = uniform(1);
    let two = uniform(2);
    let recovery = RecoveryPoolCapacities::new(two, one, two, one, two, one, one)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;

    let failure = StorageKernelResourceAuthority::establish(substitute_volume, configuration)
        .expect_err("an observation cannot establish a different volume");
    assert_eq!(failure.failure(), GovernorFailure::ObservedVolumeMismatch);
    assert_eq!(
        format!("{failure:?}"),
        "EstablishmentFailure { <redacted> }"
    );
    let (substitute_volume, configuration) = failure.into_parts();

    let authority = StorageKernelResourceAuthority::establish(observed_volume, configuration)?;
    assert_eq!(authority.observe_disk()?, DiskPressureState::Healthy);
    drop(authority);

    drop(substitute_volume);
    let reacquired = PrimaryDataVolume::acquire(&substitute_root.0, MountQualification::LocalHost)?;
    drop(reacquired);
    Ok(())
}
