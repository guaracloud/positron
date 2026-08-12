use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_kernel::{
    DiskPressureState, DiskPressureThresholds, GovernorLifecycle, GovernorPolicy,
    InventoryCardinalityLimits, MountQualification, ObservedResourceEnvironment, OperatorLimits,
    OrdinaryPoolPolicy, PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve,
    RecoveryWorkClaim, RecoveryWorkKind, RegisteredResourceBounds, ResourceAmounts,
    ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    StorageKernelResourceAuthority, TenantQuota, WorkClaim, WorkClass, WorkKind,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TemporaryRoot(PathBuf);

impl TemporaryRoot {
    fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-resource-governor-integration-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TemporaryRoot {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("failed to remove resource-governor integration root: {error}");
        }
    }
}

struct Fixture {
    authority: StorageKernelResourceAuthority,
    first: TenantId,
    second: TenantId,
    _root: TemporaryRoot,
}

fn uniform(value: u64) -> ResourceAmounts {
    ResourceAmounts::new([value; 11])
}

fn observed_amounts(observed: &ObservedResourceEnvironment) -> ResourceAmounts {
    let detected = observed.detected_capacity();
    ResourceAmounts::new(ResourceDimension::ALL.map(|dimension| detected.amount(dimension)))
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
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
        InventoryCardinalityLimits::new(2, 32)?,
        DiskPressureThresholds::new(disk / 10, disk / 5, disk / 3, disk / 2)?,
    )?;
    let first = TenantId::from_bytes([31; 16])?;
    let second = TenantId::from_bytes([32; 16])?;
    let policy = GovernorPolicy::new(
        [
            TenantQuota::new(first, 1, uniform(10))?,
            TenantQuota::new(second, 1, uniform(10))?,
        ],
        OrdinaryPoolPolicy::new(uniform(4), uniform(3), uniform(2), uniform(1))?,
    )?;
    let one = uniform(1);
    let two = uniform(2);
    let three = uniform(3);
    let recovery = RecoveryPoolCapacities::new(three, two, three, two, three, one, one)?;
    let configuration = ResourceGovernorConfiguration::new(inventory, policy, recovery)?;
    let authority = StorageKernelResourceAuthority::establish(volume, configuration)?;
    Ok(Fixture {
        authority,
        first,
        second,
        _root: root,
    })
}

#[test]
fn production_authority_admits_isolated_tenants_observes_disk_and_resizes()
-> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(
        fixture.authority.observe_disk()?,
        DiskPressureState::Healthy
    );
    let governor = fixture.authority.governor();
    let mut ingest = governor.reserve(WorkClaim::tenant(
        fixture.first,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let mut query = governor.reserve(WorkClaim::tenant(
        fixture.second,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;

    let grown = ingest.try_resize(ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?)?;
    assert_eq!(grown.added().get(ResourceDimension::MemoryBytes), 1);
    let snapshot = governor.inspect()?;
    assert_eq!(snapshot.outstanding_total(), 2);
    assert_eq!(snapshot.maximum_outstanding_reservations(), 32);
    assert_eq!(snapshot.outstanding_for(WorkClass::Ingest), 1);
    assert_eq!(snapshot.outstanding_for(WorkClass::InteractiveQueryTail), 1);

    query.cancel()?;
    drop(ingest);
    assert_eq!(governor.inspect()?.outstanding_total(), 0);
    Ok(())
}

#[test]
fn production_authority_reconciles_recovery_and_shutdown() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let governor = fixture.authority.governor();
    let ordinary = governor.reserve(WorkClaim::tenant(
        fixture.first,
        WorkKind::SecurityLifecycle,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
    )?)?;
    let mut recovery = fixture
        .authority
        .recovery()
        .reserve(RecoveryWorkClaim::system(
            RecoveryWorkKind::SafeShutdown,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
        )?)?;

    let pending = fixture.authority.begin_shutdown()?;
    assert_eq!(pending.lifecycle(), GovernorLifecycle::ShuttingDown);
    assert_eq!(pending.outstanding_ordinary(), 1);
    assert_eq!(pending.outstanding_recovery(), 1);
    assert!(!pending.complete());
    assert!(
        governor
            .reserve(WorkClaim::tenant(
                fixture.second,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1)?,
            )?)
            .is_err()
    );

    drop(ordinary);
    recovery.cancel()?;
    assert!(fixture.authority.begin_shutdown()?.complete());
    Ok(())
}
