use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{CandidateAttributeValue, ValueLimitProfile};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, DiskPressureThresholds, FixedLifecycleClockSource,
    GovernorPolicy, InstanceId, InventoryCardinalityLimits, LifecycleClock, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PreparedStoreBlock,
    PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve, RegisteredResourceBounds,
    ResourceAmounts, ResourceDimension, ResourceGovernorConfiguration, ResourceInventory,
    SegmentProtectionKey, SegmentScope, StorageKernelResourceAuthority, StoreBlockIdentity,
    TenantQuota, WorkClaim, WorkKind,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
};
use positron_signals::{LogRecord, LogStore};

pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn shared(now: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now)))
    }

    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

pub struct StepClock(AtomicU64);

impl StepClock {
    pub fn shared(now: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now)))
    }
}

pub struct TestWorkMeter;

impl positron_query::QueryWorkMeter for TestWorkMeter {
    fn units(
        &self,
        _stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(1)
    }
}

pub struct FailingClock;

impl positron_query::QueryClock for FailingClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        Err(positron_query::QueryClockFailure)
    }
}

pub struct FailingWorkMeter;

impl positron_query::QueryWorkMeter for FailingWorkMeter {
    fn units(
        &self,
        _stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Err(positron_query::QueryWorkFailure)
    }
}

pub struct SequenceClock(Mutex<VecDeque<u64>>);

impl SequenceClock {
    pub fn shared(values: impl IntoIterator<Item = u64>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(values.into_iter().collect())))
    }
}

impl positron_query::QueryClock for SequenceClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        self.0
            .lock()
            .map_err(|_| positron_query::QueryClockFailure)?
            .pop_front()
            .ok_or(positron_query::QueryClockFailure)
    }
}

pub struct FailingStageWorkMeter(pub positron_query::QueryWorkStage);

impl positron_query::QueryWorkMeter for FailingStageWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        if stage == self.0 {
            Err(positron_query::QueryWorkFailure)
        } else {
            Ok(1)
        }
    }
}

pub struct ConstantWorkMeter(pub u64);

impl positron_query::QueryWorkMeter for ConstantWorkMeter {
    fn units(
        &self,
        _stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(self.0)
    }
}

pub struct CancellingStageWorkMeter {
    stage: positron_query::QueryWorkStage,
    cancellation: Mutex<Option<positron_query::QueryCancellation>>,
}

impl CancellingStageWorkMeter {
    pub fn shared(stage: positron_query::QueryWorkStage) -> Arc<Self> {
        Arc::new(Self {
            stage,
            cancellation: Mutex::new(None),
        })
    }

    pub fn bind(
        &self,
        cancellation: positron_query::QueryCancellation,
    ) -> Result<(), positron_query::QueryWorkFailure> {
        let mut slot = self
            .cancellation
            .lock()
            .map_err(|_| positron_query::QueryWorkFailure)?;
        *slot = Some(cancellation);
        Ok(())
    }
}

impl positron_query::QueryWorkMeter for CancellingStageWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        if stage == self.stage
            && let Some(cancellation) = self
                .cancellation
                .lock()
                .map_err(|_| positron_query::QueryWorkFailure)?
                .as_ref()
        {
            cancellation.cancel();
        }
        Ok(1)
    }
}

pub struct BlockingOperatorWorkMeter {
    block_at: u64,
    operator_calls: AtomicU64,
    state: Mutex<BlockingOperatorState>,
    changed: Condvar,
}

struct BlockingOperatorState {
    blocked: bool,
    released: bool,
}

impl BlockingOperatorWorkMeter {
    pub fn shared(block_at: u64) -> Arc<Self> {
        Arc::new(Self {
            block_at,
            operator_calls: AtomicU64::new(0),
            state: Mutex::new(BlockingOperatorState {
                blocked: false,
                released: false,
            }),
            changed: Condvar::new(),
        })
    }

    pub fn wait_until_blocked(&self) -> Result<(), positron_query::QueryWorkFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| positron_query::QueryWorkFailure)?;
        while !state.blocked {
            state = self
                .changed
                .wait(state)
                .map_err(|_| positron_query::QueryWorkFailure)?;
        }
        Ok(())
    }

    pub fn release(&self) -> Result<(), positron_query::QueryWorkFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| positron_query::QueryWorkFailure)?;
        state.released = true;
        self.changed.notify_all();
        Ok(())
    }
}

impl positron_query::QueryWorkMeter for BlockingOperatorWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        if stage != positron_query::QueryWorkStage::Operators
            || self.operator_calls.fetch_add(1, Ordering::SeqCst) + 1 != self.block_at
        {
            return Ok(1);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| positron_query::QueryWorkFailure)?;
        state.blocked = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .map_err(|_| positron_query::QueryWorkFailure)?;
        }
        Ok(1)
    }
}

impl positron_query::QueryClock for StepClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        Ok(self.0.fetch_add(1, Ordering::SeqCst))
    }
}

impl positron_query::QueryClock for TestClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

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
        let candidate = NativeLogCandidate::new(
            Some(event_time),
            None,
            Some(CandidateAttributeValue::string(body.to_owned())),
            vec![],
            LogMetadata::empty(),
        );
        let PolicyEvaluation::Accepted(evaluated) =
            IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
        else {
            return Err("preserving policy rejected the query fixture".into());
        };
        let record = LogRecord::checked_evaluated(
            ValueLimitProfile::release_1_system_maximum(),
            *evaluated,
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
        8_000_000, 32, 32, 8_000_000, 2_048, 32, 32, 32, 64, 32, 2_000_000,
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
        OrdinaryPoolPolicy::new(
            with_cpu(uniform(8), 18),
            with_cpu(uniform(6), 17),
            with_cpu(uniform(4), 16),
            uniform(2),
        )?,
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

fn with_cpu(amounts: ResourceAmounts, cpu_work_units: u64) -> ResourceAmounts {
    ResourceAmounts::new([
        amounts.get(ResourceDimension::MemoryBytes),
        amounts.get(ResourceDimension::QueueSlots),
        amounts.get(ResourceDimension::TaskSlots),
        amounts.get(ResourceDimension::BufferCacheBytes),
        amounts.get(ResourceDimension::BatchItems),
        amounts.get(ResourceDimension::LeaseSlots),
        amounts.get(ResourceDimension::RetrySlots),
        amounts.get(ResourceDimension::IoPermits),
        cpu_work_units,
        amounts.get(ResourceDimension::FileDescriptors),
        amounts.get(ResourceDimension::DiskHeadroomBytes),
    ])
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
