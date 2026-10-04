use super::*;

static NEXT_CATALOG_ROOT: AtomicU64 = AtomicU64::new(0);

pub(super) struct CatalogRoot(pub(super) PathBuf);

impl CatalogRoot {
    pub(super) fn new() -> Result<Self, std::io::Error> {
        let sequence = NEXT_CATALOG_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-maintenance-catalog-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for CatalogRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn nonzero_id(last: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[15] = last;
    bytes
}

pub(super) fn task(
    identity: u8,
    class: MaintenanceTaskClass,
    trigger: MaintenanceTrigger,
    _priority: MaintenancePriority,
    inputs: Vec<MaintenanceObjectId>,
) -> MaintenanceTask {
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("stable task identity"),
        class,
        MaintenanceScope::system(),
        trigger,
        MaintenancePreconditions::new(4, 9).expect("valid preconditions"),
        inputs,
        Vec::new(),
        ResourceAmounts::new([64, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
    )
    .expect("bounded task")
}

pub(super) fn authority() -> (StorageKernelResourceAuthority, TenantId) {
    let tenant = TenantId::from_bytes([90; 16]).expect("test tenant");
    let uniform = |amount| ResourceAmounts::new([amount; 11]);
    let cardinality = InventoryCardinalityLimits::new(1, 8).expect("cardinality");
    let raw = uniform(100_000);
    let inventory = ResourceInventory::new(
        DetectedCapacity::new(raw).expect("detected capacity"),
        OperatorLimits::new(raw).expect("operator limits"),
        RecoveryReserve::new(uniform(10)).expect("recovery reserve"),
        cardinality,
        DiskPressureThresholds::new(20, 30, 40, 50).expect("pressure thresholds"),
        DiskObservation::new(100),
    )
    .expect("inventory");
    let policy = GovernorPolicy::new(
        [TenantQuota::new(tenant, 1, uniform(50)).expect("tenant quota")],
        OrdinaryPoolPolicy::new(uniform(20), uniform(15), uniform(10), uniform(5))
            .expect("ordinary pools"),
    )
    .expect("policy");
    let recovery_pools = RecoveryPoolCapacities::new(
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(2),
        uniform(1),
        uniform(1),
    )
    .expect("recovery pools");
    (
        StorageKernelResourceAuthority::establish_for_test(inventory, policy, recovery_pools)
            .expect("resource authority"),
        tenant,
    )
}

pub(super) fn tenant_task(
    identity: u8,
    tenant: TenantId,
    reservations: ResourceAmounts,
) -> MaintenanceTask {
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("identity"),
        MaintenanceTaskClass::Compaction,
        MaintenanceScope::tenant(tenant),
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(1, 1).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        reservations,
    )
    .expect("task")
}

pub(super) fn catalog_task(identity: u8) -> MaintenanceTask {
    MaintenanceTask::with_contract(
        MaintenanceTaskId::new([identity; 16]).expect("stable task identity"),
        MaintenanceTaskClass::RepositoryVerification,
        MaintenanceScope::system(),
        MaintenanceTrigger::Event,
        MaintenancePreconditions::new(4, 9).expect("preconditions"),
        Vec::new(),
        Vec::new(),
        ResourceAmounts::new([1; 11]),
    )
    .expect("bounded task")
}

pub(super) fn snapshot_lease_expiry_task(
    identity: crate::SnapshotLeaseId,
    scope: MaintenanceScope,
    lease_object: crate::CatalogObjectId,
) -> MaintenanceTask {
    MaintenanceTask::with_contract_not_before(
        MaintenanceTaskId::new(identity.to_bytes()).expect("lease task identity"),
        MaintenanceTaskClass::SnapshotLeaseExpiry,
        scope,
        MaintenanceTrigger::Scheduled,
        MaintenancePreconditions::new(7, 1).expect("preconditions"),
        vec![MaintenanceObjectId::new(lease_object.to_bytes()).expect("lease object input")],
        Vec::new(),
        ResourceAmounts::new([1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0]),
        10,
    )
    .expect("snapshot expiry task")
}
