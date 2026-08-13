use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskPressureThresholds, FixedLifecycleClockSource,
    GovernorPolicy, InstanceId, InventoryCardinalityLimits, LifecycleClock, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PreparedStoreBlock,
    PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds,
    ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    SegmentProtectionKey, SegmentScope, StorageKernelResourceAuthority, StoreBlockIdentity,
    TenantQuota, WorkClaim, WorkKind,
};
use positron_signals::{LogRecord, LogStore, PolicyProvenance};

const DIMENSIONS: usize = 11;
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

pub struct TemporaryRoots(PathBuf);

impl TemporaryRoots {
    pub fn new(label: &str) -> Result<Self, std::io::Error> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "positron-query-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::create_dir(path.join("data"))?;
        fs::create_dir(path.join("secrets"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.join("secrets"), fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(path))
    }

    pub fn data(&self) -> PathBuf {
        self.0.join("data")
    }

    pub fn secrets(&self) -> PathBuf {
        self.0.join("secrets")
    }
}

impl Drop for TemporaryRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub struct KernelFixture {
    pub authority: &'static StorageKernelResourceAuthority,
    catalog: &'static Catalog<'static>,
    ledger: Option<ActiveSegmentLedger<'static, 'static>>,
    tenant: TenantId,
    shard: VirtualShardId,
    _root: TemporaryRoots,
}

impl KernelFixture {
    pub fn new(tenant: TenantId, label: &str) -> Result<Self, Box<dyn Error>> {
        let root = TemporaryRoots::new(label)?;
        let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
        let authority = Box::leak(Box::new(establish_authority(volume, tenant)?));
        let catalog = Box::leak(Box::new(Catalog::open(
            authority,
            InstanceId::new([0x31; 16])?,
            CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
        )?));
        let shard = VirtualShardId::new(1)?;
        let ledger = ActiveSegmentLedger::open(
            authority,
            catalog,
            SegmentScope::new(tenant, SignalKind::Logs, shard),
            SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
        )?;
        Ok(Self {
            authority,
            catalog,
            ledger: Some(ledger),
            tenant,
            shard,
            _root: root,
        })
    }

    pub fn ledger(&self) -> Result<&ActiveSegmentLedger<'static, 'static>, Box<dyn Error>> {
        self.ledger
            .as_ref()
            .ok_or_else(|| "ledger unavailable".into())
    }

    pub fn seal_and_reopen(&mut self) -> Result<(), Box<dyn Error>> {
        let ledger = self.ledger.take().ok_or("ledger unavailable")?;
        ledger.seal()?;
        self.ledger = Some(ActiveSegmentLedger::open(
            self.authority,
            self.catalog,
            SegmentScope::new(self.tenant, SignalKind::Logs, self.shard),
            SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
        )?);
        Ok(())
    }

    pub fn append_log(
        &self,
        body: &str,
        event_time: i64,
        identity: u8,
    ) -> Result<(), Box<dyn Error>> {
        let record = LogRecord::checked_minimal(
            Some(event_time),
            Some(body.to_owned()),
            vec![],
            PolicyProvenance::new(1, [0x41; 32], vec![])?,
        )?;
        let capacity = self.authority.governor().reserve(WorkClaim::tenant(
            self.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        let block = LogStore::new().prepare(
            capacity,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(50))),
            self.tenant,
            self.shard,
            StoreBlockIdentity::new([identity; 16])?,
            vec![record],
        )?;
        self.ledger()?.append(block.into_store_block())?;
        Ok(())
    }

    pub fn append_malformed_log_block(&self, identity: u8) -> Result<(), Box<dyn Error>> {
        let block = PreparedStoreBlock::new(
            SegmentScope::new(self.tenant, SignalKind::Logs, self.shard),
            StoreBlockIdentity::new([identity; 16])?,
            b"not-a-canonical-log-block".to_vec(),
        )?;
        self.ledger()?.append(block)?;
        Ok(())
    }
}

fn establish_authority(
    volume: positron_kernel::OwnedPrimaryDataVolume,
    tenant: TenantId,
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
    let ordinary_capacity = ResourceAmounts::new([
        8_000_000, 32, 32, 8_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
    ]);
    let raw = add(
        add(recovery_capacity, ordinary_capacity)?,
        cardinality.governor_bootstrap_overhead(1)?,
    )?;
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
    StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|_| "kernel authority establishment failed".into())
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
