use std::fs;
use std::path::PathBuf;

use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskObservation, DiskPressureThresholds, GovernorFailure, GovernorPolicy,
    InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPoolPolicy, PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve,
    ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota, VolumeFailureCode,
};

use super::resource_governor_test_support as resource_governor_support;

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new(suffix: &str) -> Result<Self, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "positron-resource-authority-test-{}-{suffix}",
            std::process::id(),
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove authority test root: {error}");
        }
    }
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn configuration(
    volume: &positron_kernel::OwnedPrimaryDataVolume,
    tenant: TenantId,
) -> Result<ResourceGovernorConfiguration, Box<dyn std::error::Error>> {
    let operator = resource_governor_support::raw_capacity_for_governed_work(uniform(29), 6)?;
    let observed = ObservedResourceEnvironment::for_test(
        volume,
        operator,
        DiskObservation::new(operator.get(ResourceDimension::DiskHeadroomBytes)),
    )?;
    let inventory = ResourceInventory::new_observed(
        observed,
        OperatorLimits::new(resource_governor_support::raw_capacity_for_governed_work(
            uniform(29),
            6,
        )?)?,
        RecoveryReserve::new(uniform(10))?,
        InventoryCardinalityLimits::new(1, 6)?,
        DiskPressureThresholds::new(10, 11, 12, 13)?,
    )?;
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(19))?],
        OrdinaryPoolPolicy::new(uniform(4), uniform(4), uniform(3), uniform(2))?,
    )?;
    let minimum = uniform(1);
    let dual = uniform(2);
    Ok(ResourceGovernorConfiguration::new(
        inventory,
        policy,
        RecoveryPoolCapacities::new(dual, minimum, dual, minimum, dual, minimum, minimum)?,
    )?)
}

#[test]
fn root_authority_owns_the_volume_lock_for_its_complete_lifetime()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::from_bytes([91; 16])?;
    let root = TemporaryRoot::new("lifetime")?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let configuration = configuration(&volume, tenant)?;
    let authority = StorageKernelResourceAuthority::establish(volume, configuration)?;
    let failure = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)
        .expect_err("the live root authority must retain the owned volume lock");
    assert_eq!(failure.code(), VolumeFailureCode::Busy);

    drop(authority);

    let reacquired = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    drop(reacquired);
    Ok(())
}

#[test]
fn deterministic_environment_remains_bound_to_its_exact_volume()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::from_bytes([92; 16])?;
    let observed_root = TemporaryRoot::new("observed")?;
    let substitute_root = TemporaryRoot::new("substitute")?;
    let observed_volume =
        PrimaryDataVolume::acquire(&observed_root.0, MountQualification::LocalHost)?;
    let substitute_volume =
        PrimaryDataVolume::acquire(&substitute_root.0, MountQualification::LocalHost)?;
    let configuration = configuration(&observed_volume, tenant)?;

    let mismatch = StorageKernelResourceAuthority::establish(substitute_volume, configuration)
        .expect_err("deterministic observation must reject a different volume");
    assert_eq!(mismatch.failure(), GovernorFailure::ObservedVolumeMismatch);
    let (substitute_volume, configuration) = mismatch.into_parts();
    let authority = StorageKernelResourceAuthority::establish(observed_volume, configuration)?;

    drop(authority);
    drop(substitute_volume);
    Ok(())
}
