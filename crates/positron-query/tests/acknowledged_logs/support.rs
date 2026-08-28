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
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret,
    ControlTokenProtector, DiskObservation, DiskPressureThresholds, FixedLifecycleClockSource,
    FormatEpoch, GovernanceFixtureObject, GovernanceFixtureTarget, GovernorFailure, GovernorPolicy,
    InstanceId, InventoryCardinalityLimits, LifecycleClock, MountQualification,
    ObservedResourceEnvironment, OperatorLimits, OrdinaryPoolPolicy, PreparedStoreBlock,
    PrimaryDataVolume, RecoveryPoolCapacities, RecoveryReserve, ResourceAmounts, ResourceDimension,
    ResourceGovernorConfiguration, ResourceInventory, SegmentProtectionKey, SegmentScope,
    StorageKernelResourceAuthority, StoreBlockIdentity, TenantQuota, TransactionId, WorkClaim,
    WorkKind,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_runtime::GovernanceTestFixture;
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

pub struct LifecycleTransitionClock {
    catalog: &'static Catalog<'static>,
    state: u8,
    transaction: u8,
    transitioned: std::sync::atomic::AtomicBool,
}

impl LifecycleTransitionClock {
    pub fn shared(catalog: &'static Catalog<'static>, state: u8, transaction: u8) -> Arc<Self> {
        Arc::new(Self {
            catalog,
            state,
            transaction,
            transitioned: std::sync::atomic::AtomicBool::new(false),
        })
    }
}

impl positron_query::QueryClock for LifecycleTransitionClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        if !self
            .transitioned
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            publish_lifecycle_at_catalog_for_test(self.catalog, self.state, self.transaction)
                .map_err(|_| positron_query::QueryClockFailure)?;
        }
        Ok(101)
    }
}

pub struct TestWorkMeter;

impl positron_query::QueryWorkMeter for TestWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(u64::from(
            stage != positron_query::QueryWorkStage::ScanDecode,
        ))
    }
}

pub struct FailingClock;

impl positron_query::QueryClock for FailingClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        Err(positron_query::QueryClockFailure)
    }
}

pub struct PeriodicFailingClock(AtomicU64);

impl PeriodicFailingClock {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(0)))
    }
}

impl positron_query::QueryClock for PeriodicFailingClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        let call = self.0.fetch_add(1, Ordering::SeqCst);
        if call % 4 == 3 {
            Err(positron_query::QueryClockFailure)
        } else {
            Ok(100)
        }
    }
}

pub struct FailAfterArmClock {
    armed: std::sync::atomic::AtomicBool,
    calls: AtomicU64,
    fail_after: u64,
}

impl FailAfterArmClock {
    pub fn shared(fail_after: u64) -> Arc<Self> {
        Arc::new(Self {
            armed: std::sync::atomic::AtomicBool::new(false),
            calls: AtomicU64::new(0),
            fail_after,
        })
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl positron_query::QueryClock for FailAfterArmClock {
    fn now_seconds(&self) -> Result<u64, positron_query::QueryClockFailure> {
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(100);
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) >= self.fail_after {
            Err(positron_query::QueryClockFailure)
        } else {
            Ok(100)
        }
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

pub struct FailAfterArmOutputMeter {
    armed: std::sync::atomic::AtomicBool,
    output_calls: AtomicU64,
    fail_after: u64,
}

pub struct OutputOnlyWorkMeter;

impl FailAfterArmOutputMeter {
    pub fn shared(fail_after: u64) -> Arc<Self> {
        Arc::new(Self {
            armed: std::sync::atomic::AtomicBool::new(false),
            output_calls: AtomicU64::new(0),
            fail_after,
        })
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl positron_query::QueryWorkMeter for FailAfterArmOutputMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        if stage == positron_query::QueryWorkStage::Output
            && self.armed.load(Ordering::SeqCst)
            && self.output_calls.fetch_add(1, Ordering::SeqCst) >= self.fail_after
        {
            Err(positron_query::QueryWorkFailure)
        } else {
            Ok(0)
        }
    }
}

impl positron_query::QueryWorkMeter for OutputOnlyWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(u64::from(stage == positron_query::QueryWorkStage::Output))
    }
}

impl positron_query::QueryWorkMeter for FailingStageWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        if stage == self.0 {
            Err(positron_query::QueryWorkFailure)
        } else if stage == positron_query::QueryWorkStage::ScanDecode {
            Ok(0)
        } else {
            Ok(1)
        }
    }
}

pub struct ConstantWorkMeter(pub u64);

pub struct MergeWorkMeter;

impl positron_query::QueryWorkMeter for MergeWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(u64::from(
            stage == positron_query::QueryWorkStage::Operators,
        ))
    }
}

pub struct StageCountingWorkMeter {
    calls: [AtomicU64; 4],
}

impl StageCountingWorkMeter {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self {
            calls: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }

    pub fn calls(&self, stage: positron_query::QueryWorkStage) -> u64 {
        self.calls[stage_index(stage)].load(Ordering::SeqCst)
    }
}

impl positron_query::QueryWorkMeter for StageCountingWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        self.calls[stage_index(stage)].fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }
}

const fn stage_index(stage: positron_query::QueryWorkStage) -> usize {
    match stage {
        positron_query::QueryWorkStage::Parse => 0,
        positron_query::QueryWorkStage::ScanDecode => 1,
        positron_query::QueryWorkStage::Operators => 2,
        positron_query::QueryWorkStage::Output => 3,
    }
}

pub struct ZeroScanWorkMeter;

impl positron_query::QueryWorkMeter for ZeroScanWorkMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(u64::from(
            stage != positron_query::QueryWorkStage::ScanDecode,
        ))
    }
}

impl positron_query::QueryWorkMeter for ConstantWorkMeter {
    fn units(
        &self,
        _stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        Ok(self.0)
    }
}

pub fn zero_work_service<'kernel, 'catalog, 'ledger>(
    governor: positron_kernel::ResourceGovernor<'kernel>,
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    batch_limit: u16,
) -> positron_query::QueryService<'kernel, 'catalog, 'ledger> {
    positron_query::QueryService::with_runtime(
        governor,
        ledger,
        batch_limit,
        TestClock::shared(100),
        Arc::new(ConstantWorkMeter(0)),
    )
}

pub fn zero_work_clock_service<'kernel, 'catalog, 'ledger>(
    governor: positron_kernel::ResourceGovernor<'kernel>,
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    batch_limit: u16,
    clock: Arc<dyn positron_query::QueryClock>,
) -> positron_query::QueryService<'kernel, 'catalog, 'ledger> {
    positron_query::QueryService::with_runtime(
        governor,
        ledger,
        batch_limit,
        clock,
        Arc::new(ConstantWorkMeter(0)),
    )
}

pub fn stage_work_service<'kernel, 'catalog, 'ledger>(
    governor: positron_kernel::ResourceGovernor<'kernel>,
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    batch_limit: u16,
) -> positron_query::QueryService<'kernel, 'catalog, 'ledger> {
    positron_query::QueryService::with_runtime(
        governor,
        ledger,
        batch_limit,
        TestClock::shared(100),
        Arc::new(ZeroScanWorkMeter),
    )
}

pub(crate) fn tail_cursor_with_cpu_progress(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    cpu_work_units: u64,
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    rewrite_tail_cursor(protector, cursor, |payload| {
        const CPU_WORK_UNITS_OFFSET: usize = 202;
        let cpu_end = CPU_WORK_UNITS_OFFSET
            .checked_add(std::mem::size_of::<u64>())
            .ok_or("tail cursor CPU field offset overflow")?;
        payload
            .get_mut(CPU_WORK_UNITS_OFFSET..cpu_end)
            .ok_or("tail cursor CPU field missing")?
            .copy_from_slice(&cpu_work_units.to_be_bytes());
        Ok(())
    })
}

pub(crate) fn tail_cursor_with_source_binding(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    snapshot_generation: Option<u64>,
    frontier: Option<u64>,
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    rewrite_tail_cursor(protector, cursor, |payload| {
        const BIND_MAGIC: &[u8] = b"TB01";
        let bindings_start = payload
            .windows(BIND_MAGIC.len())
            .position(|window| window == BIND_MAGIC)
            .ok_or("tail cursor source bindings missing")?;
        let generation_start = bindings_start
            .checked_add(6 + 32)
            .ok_or("tail cursor generation offset overflow")?;
        if let Some(snapshot_generation) = snapshot_generation {
            let generation_end = generation_start
                .checked_add(std::mem::size_of::<u64>())
                .ok_or("tail cursor generation field overflow")?;
            payload
                .get_mut(generation_start..generation_end)
                .ok_or("tail cursor generation field missing")?
                .copy_from_slice(&snapshot_generation.to_be_bytes());
        }
        if let Some(frontier) = frontier {
            let frontier_start = generation_start
                .checked_add(std::mem::size_of::<u64>())
                .ok_or("tail cursor frontier offset overflow")?
                .checked_add(std::mem::size_of::<u64>())
                .ok_or("tail cursor frontier offset overflow")?;
            let frontier_end = frontier_start
                .checked_add(std::mem::size_of::<u64>())
                .ok_or("tail cursor frontier field overflow")?;
            payload
                .get_mut(frontier_start..frontier_end)
                .ok_or("tail cursor frontier field missing")?
                .copy_from_slice(&frontier.to_be_bytes());
        }
        Ok(())
    })
}

pub(crate) fn tail_cursor_with_source_lease(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    lease: [u8; 16],
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    rewrite_tail_cursor(protector, cursor, |payload| {
        const BIND_MAGIC: &[u8] = b"TB01";
        let bindings_start = payload
            .windows(BIND_MAGIC.len())
            .position(|window| window == BIND_MAGIC)
            .ok_or("tail cursor source bindings missing")?;
        let lease_start = bindings_start
            .checked_add(6 + 32 + 8)
            .ok_or("tail cursor source lease offset overflow")?;
        let lease_end = lease_start
            .checked_add(lease.len())
            .ok_or("tail cursor source lease field overflow")?;
        payload
            .get_mut(lease_start..lease_end)
            .ok_or("tail cursor source lease field missing")?
            .copy_from_slice(&lease);
        Ok(())
    })
}

pub(crate) fn tail_cursor_with_position(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    position_index: usize,
    position: u64,
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    rewrite_tail_cursor(protector, cursor, |payload| {
        const PREFIX_BYTES: usize = 260;
        const POSITION_BYTES: usize = 16;
        let start = PREFIX_BYTES
            .checked_add(
                position_index
                    .checked_mul(POSITION_BYTES)
                    .ok_or("position overflow")?,
            )
            .ok_or("position offset overflow")?;
        let position_start = start.checked_add(4).ok_or("position field overflow")?;
        let position_end = position_start
            .checked_add(8)
            .ok_or("position field overflow")?;
        payload
            .get_mut(position_start..position_end)
            .ok_or("position field missing")?
            .copy_from_slice(&position.to_be_bytes());
        *payload
            .get_mut(start.checked_add(14).ok_or("position flag overflow")?)
            .ok_or("position flag missing")? = 1;
        Ok(())
    })
}

pub(crate) fn tail_cursor_with_trailing_byte(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    const AUTH_BYTES: usize = 32;
    let bytes = cursor.as_bytes();
    let payload_len = bytes
        .len()
        .checked_sub(AUTH_BYTES)
        .ok_or("cursor tag missing")?;
    let mut payload = bytes
        .get(..payload_len)
        .ok_or("cursor payload missing")?
        .to_vec();
    payload.push(0);
    let authentication = protector.authenticate_query_cursor(b"tail-cursor-v3", &payload)?;
    payload.extend_from_slice(&authentication.tag());
    Ok(positron_query::TailCursor::from_bytes(&payload)?)
}

pub(crate) fn tail_cursor_with_snapshot_identity(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    identity: [u8; 32],
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    rewrite_tail_cursor(protector, cursor, |payload| {
        const BIND_MAGIC: &[u8] = b"TB01";
        let bindings_start = payload
            .windows(BIND_MAGIC.len())
            .position(|window| window == BIND_MAGIC)
            .ok_or("tail cursor source bindings missing")?;
        let identity_start = bindings_start
            .checked_add(BIND_MAGIC.len() + std::mem::size_of::<u16>())
            .ok_or("tail cursor snapshot identity offset overflow")?;
        let identity_end = identity_start
            .checked_add(identity.len())
            .ok_or("tail cursor snapshot identity field overflow")?;
        payload
            .get_mut(identity_start..identity_end)
            .ok_or("tail cursor snapshot identity field missing")?
            .copy_from_slice(&identity);
        Ok(())
    })
}

pub(crate) fn tail_cursor_with_delivery_sequence(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    sequence: u64,
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    rewrite_tail_cursor(protector, cursor, |payload| {
        const DELIVERY_MAGIC: &[u8] = b"DLV1";
        let delivery_start = payload
            .windows(DELIVERY_MAGIC.len())
            .position(|window| window == DELIVERY_MAGIC)
            .ok_or("tail cursor delivery marker missing")?;
        let sequence_start = delivery_start
            .checked_add(DELIVERY_MAGIC.len())
            .ok_or("tail cursor delivery sequence offset overflow")?;
        let sequence_end = sequence_start
            .checked_add(std::mem::size_of::<u64>())
            .ok_or("tail cursor delivery sequence field overflow")?;
        payload
            .get_mut(sequence_start..sequence_end)
            .ok_or("tail cursor delivery sequence field missing")?
            .copy_from_slice(&sequence.to_be_bytes());
        Ok(())
    })
}

fn rewrite_tail_cursor(
    protector: &ControlTokenProtector<'_>,
    cursor: &positron_query::TailCursor,
    rewrite: impl FnOnce(&mut [u8]) -> Result<(), Box<dyn Error>>,
) -> Result<positron_query::TailCursor, Box<dyn Error>> {
    const MAGIC: &[u8] = b"POSTCUR3";
    const VERSION: [u8; 2] = 2_u16.to_be_bytes();
    const AUTH_BYTES: usize = 32;

    let mut bytes = cursor.as_bytes().to_vec();
    if bytes.get(..MAGIC.len()) != Some(MAGIC)
        || bytes.get(MAGIC.len()..MAGIC.len() + VERSION.len()) != Some(VERSION.as_slice())
    {
        return Err("unsupported tail cursor wire version".into());
    }
    let payload_len = bytes
        .len()
        .checked_sub(AUTH_BYTES)
        .ok_or("tail cursor authentication tag missing")?;
    rewrite(
        bytes
            .get_mut(..payload_len)
            .ok_or("tail cursor payload missing")?,
    )?;
    let authentication = protector.authenticate_query_cursor(
        b"tail-cursor-v3",
        bytes
            .get(..payload_len)
            .ok_or("tail cursor payload missing")?,
    )?;
    bytes
        .get_mut(payload_len..)
        .ok_or("tail cursor authentication tag missing")?
        .copy_from_slice(&authentication.tag());
    Ok(positron_query::TailCursor::from_bytes(&bytes)?)
}

pub fn merge_work_service<'kernel, 'catalog, 'ledger>(
    governor: positron_kernel::ResourceGovernor<'kernel>,
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    batch_limit: u16,
) -> positron_query::QueryService<'kernel, 'catalog, 'ledger> {
    positron_query::QueryService::with_runtime(
        governor,
        ledger,
        batch_limit,
        TestClock::shared(100),
        Arc::new(MergeWorkMeter),
    )
}

pub fn stage_work_clock_service<'kernel, 'catalog, 'ledger>(
    governor: positron_kernel::ResourceGovernor<'kernel>,
    ledger: &'ledger ActiveSegmentLedger<'kernel, 'catalog>,
    batch_limit: u16,
    clock: Arc<dyn positron_query::QueryClock>,
) -> positron_query::QueryService<'kernel, 'catalog, 'ledger> {
    positron_query::QueryService::with_runtime(
        governor,
        ledger,
        batch_limit,
        clock,
        Arc::new(ZeroScanWorkMeter),
    )
}

pub struct CancellingStageWorkMeter {
    stage: positron_query::QueryWorkStage,
    cancellation: Mutex<Option<positron_query::QueryCancellation>>,
}

pub struct CancellingOperatorCallMeter {
    stage: positron_query::QueryWorkStage,
    cancel_at: u64,
    calls: AtomicU64,
    cancellation: Mutex<Option<positron_query::QueryCancellation>>,
}

impl CancellingOperatorCallMeter {
    pub fn shared(cancel_at: u64) -> Arc<Self> {
        Arc::new(Self {
            stage: positron_query::QueryWorkStage::Operators,
            cancel_at,
            calls: AtomicU64::new(0),
            cancellation: Mutex::new(None),
        })
    }

    pub fn shared_for_stage(stage: positron_query::QueryWorkStage, cancel_at: u64) -> Arc<Self> {
        Arc::new(Self {
            stage,
            cancel_at,
            calls: AtomicU64::new(0),
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

impl positron_query::QueryWorkMeter for CancellingOperatorCallMeter {
    fn units(
        &self,
        stage: positron_query::QueryWorkStage,
    ) -> Result<u64, positron_query::QueryWorkFailure> {
        if stage == self.stage {
            if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.cancel_at
                && let Some(cancellation) = self
                    .cancellation
                    .lock()
                    .map_err(|_| positron_query::QueryWorkFailure)?
                    .as_ref()
            {
                cancellation.cancel();
            }
            Ok(1)
        } else {
            Ok(0)
        }
    }
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
        Ok(u64::from(
            stage != positron_query::QueryWorkStage::ScanDecode,
        ))
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
        if stage != positron_query::QueryWorkStage::Operators {
            return Ok(0);
        }
        if self.operator_calls.fetch_add(1, Ordering::SeqCst) + 1 != self.block_at {
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

pub fn publish_lifecycle_at_catalog_for_test(
    catalog: &Catalog<'_>,
    state: u8,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            let bytes = basis.object(identity)?.ok_or("missing Catalog object")?;
            let mut bytes = bytes.to_vec();
            if bytes.starts_with(b"POSGOV01")
                || bytes.starts_with(b"POSGOV02")
                || bytes.starts_with(b"POSGOV03")
            {
                let offset = bytes.len().checked_sub(5).ok_or("identity too short")?;
                bytes[offset] = state;
            }
            CatalogObject::new(bytes).map_err(|failure| -> Box<dyn Error> { Box::new(failure) })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new([transaction; 16])?,
            FormatEpoch::CATALOG_V1,
            std::mem::take(&mut objects),
        )?,
        None,
    )?;
    Ok(())
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

    pub fn new_with_identity(
        tenant: TenantId,
        label: &str,
        identity: &GovernanceTestFixture,
    ) -> Result<Self, Box<dyn Error>> {
        let fixture = Self::new(tenant, label)?;
        identity.install_into(&fixture)?;
        Ok(fixture)
    }

    pub fn ledger(&self) -> Result<&ActiveSegmentLedger<'static, 'static>, Box<dyn Error>> {
        self.ledger
            .as_ref()
            .ok_or_else(|| "ledger unavailable".into())
    }

    pub fn publish_lifecycle_for_test(
        &self,
        state: u8,
        transaction: u8,
    ) -> Result<(), Box<dyn Error>> {
        publish_lifecycle_at_catalog_for_test(self.catalog, state, transaction)
    }

    pub fn catalog_for_test(&self) -> &'static Catalog<'static> {
        self.catalog
    }

    pub fn catalog_data_root_for_test(&self) -> PathBuf {
        self._root.0.join("catalog")
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

    pub fn reopen_ledger(&mut self) -> Result<(), Box<dyn Error>> {
        let ledger = self.ledger.take().ok_or("ledger unavailable")?;
        drop(ledger);
        let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(
            101_000_000_000,
        )));
        self.ledger = Some(ActiveSegmentLedger::open_with_clock(
            self.authority,
            self.catalog,
            SegmentScope::new(self.tenant, SignalKind::Logs, self.shard),
            SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
            &clock,
        )?);
        Ok(())
    }

    pub fn append_log(
        &self,
        body: &str,
        event_time: i64,
        identity: u8,
    ) -> Result<(), Box<dyn Error>> {
        self.append_log_bodies(
            vec![Some(CandidateAttributeValue::string(body.to_owned()))],
            event_time,
            identity,
        )
    }

    pub fn append_log_bodies(
        &self,
        bodies: Vec<Option<CandidateAttributeValue>>,
        event_time: i64,
        identity: u8,
    ) -> Result<(), Box<dyn Error>> {
        self.append_logs(
            bodies
                .into_iter()
                .map(|body| (Some(event_time), body))
                .collect(),
            identity,
        )
    }

    pub fn append_logs(
        &self,
        candidates: Vec<(Option<i64>, Option<CandidateAttributeValue>)>,
        identity: u8,
    ) -> Result<(), Box<dyn Error>> {
        let ledger = self.ledger()?;
        self.append_logs_to(ledger, self.shard, candidates, identity)
    }

    pub fn append_logs_to(
        &self,
        ledger: &ActiveSegmentLedger<'static, 'static>,
        shard: VirtualShardId,
        candidates: Vec<(Option<i64>, Option<CandidateAttributeValue>)>,
        identity: u8,
    ) -> Result<(), Box<dyn Error>> {
        let mut records = Vec::new();
        records.try_reserve_exact(candidates.len())?;
        for (event_time, body) in candidates {
            let candidate =
                NativeLogCandidate::new(event_time, None, body, vec![], LogMetadata::empty());
            let PolicyEvaluation::Accepted(evaluated) =
                IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
            else {
                return Err("preserving policy rejected the query fixture".into());
            };
            records.push(LogRecord::checked_evaluated(
                ValueLimitProfile::release_1_system_maximum(),
                *evaluated,
            )?);
        }
        let capacity = self.authority.governor().reserve(WorkClaim::tenant(
            self.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        let block = LogStore::new().prepare(
            capacity,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(50))),
            self.tenant,
            shard,
            StoreBlockIdentity::new([identity; 16])?,
            records,
        )?;
        ledger.append(block.into_store_block())?;
        Ok(())
    }

    pub fn append_attribute_logs(
        &self,
        candidates: Vec<(Option<i64>, Vec<NativeLogAttribute>)>,
        identity: u8,
    ) -> Result<(), Box<dyn Error>> {
        let mut records = Vec::new();
        records.try_reserve_exact(candidates.len())?;
        for (event_time, attributes) in candidates {
            let candidate =
                NativeLogCandidate::new(event_time, None, None, attributes, LogMetadata::empty());
            let PolicyEvaluation::Accepted(evaluated) =
                IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
            else {
                return Err("preserving policy rejected the attribute query fixture".into());
            };
            records.push(LogRecord::checked_evaluated(
                ValueLimitProfile::release_1_system_maximum(),
                *evaluated,
            )?);
        }
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
            records,
        )?;
        self.ledger()?.append(block.into_store_block())?;
        Ok(())
    }

    pub fn append_indexed_attribute_logs(
        &self,
        candidates: Vec<(Option<i64>, Vec<NativeLogAttribute>)>,
        identity: u8,
        indexed_path: &positron_signals::SchemaPath,
    ) -> Result<positron_signals::SchemaSessionStore, Box<dyn Error>> {
        let schema_budget = positron_signals::SchemaBudget::new(8, 200_000, 8_000, 8_000)?;
        let schema_capacity = self.authority.governor().reserve(WorkClaim::tenant(
            self.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 200_000)?,
        )?)?;
        let mut schema =
            positron_signals::SchemaSessionStore::new(schema_capacity, self.tenant, schema_budget)?;
        let mut records = Vec::new();
        records.try_reserve_exact(candidates.len())?;
        for (event_time, attributes) in candidates {
            let candidate =
                NativeLogCandidate::new(event_time, None, None, attributes, LogMetadata::empty());
            let PolicyEvaluation::Accepted(evaluated) =
                IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
            else {
                return Err("preserving policy rejected the indexed query fixture".into());
            };
            records.push(LogRecord::checked_evaluated(
                ValueLimitProfile::release_1_system_maximum(),
                *evaluated,
            )?);
        }
        let delta = schema.stage_group(&mut records)?;
        let capacity = self.authority.governor().reserve(WorkClaim::tenant(
            self.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        let block = LogStore::new()
            .prepare(
                capacity,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(50))),
                self.tenant,
                self.shard,
                StoreBlockIdentity::new([identity; 16])?,
                records,
            )?
            .into_store_block();
        let digest = block.content_digest()?;
        self.ledger()?.append(block)?;
        let block_identity = StoreBlockIdentity::new([identity; 16])?;
        schema.commit(delta, block_identity, digest)?;
        let snapshot = self.ledger()?.snapshot()?;
        let indexed_block = snapshot
            .blocks()
            .iter()
            .find(|block| block.identity() == block_identity)
            .ok_or("indexed block missing from fixture snapshot")?;
        let mut query_update = schema.stage_query_update()?;
        query_update.record_query_use(indexed_path)?;
        query_update.index_replayed_query_path(
            self.tenant,
            &snapshot,
            indexed_block,
            indexed_path,
        )?;
        schema.commit_query_update(query_update)?;
        Ok(schema)
    }

    pub fn append_indexed_text_logs(
        &self,
        bodies: Vec<&str>,
        identity: u8,
    ) -> Result<positron_signals::SchemaSessionStore, Box<dyn Error>> {
        let schema_budget = positron_signals::SchemaBudget::new(8, 200_000, 8_000, 8_000)?;
        let schema_capacity = self.authority.governor().reserve(WorkClaim::tenant(
            self.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 200_000)?,
        )?)?;
        let mut schema =
            positron_signals::SchemaSessionStore::new(schema_capacity, self.tenant, schema_budget)?;
        let mut records = Vec::new();
        records.try_reserve_exact(bodies.len())?;
        for (event_time, body) in bodies.into_iter().enumerate() {
            let event_time = i64::try_from(event_time + 20)?;
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
                return Err("preserving policy rejected the text query fixture".into());
            };
            records.push(LogRecord::checked_evaluated(
                ValueLimitProfile::release_1_system_maximum(),
                *evaluated,
            )?);
        }
        let delta = schema.stage_group(&mut records)?;
        let capacity = self.authority.governor().reserve(WorkClaim::tenant(
            self.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
        )?)?;
        let block = LogStore::new()
            .prepare(
                capacity,
                &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(50))),
                self.tenant,
                self.shard,
                StoreBlockIdentity::new([identity; 16])?,
                records,
            )?
            .into_store_block();
        let digest = block.content_digest()?;
        self.ledger()?.append(block)?;
        schema.commit(delta, StoreBlockIdentity::new([identity; 16])?, digest)?;
        Ok(schema)
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

impl GovernanceFixtureTarget for KernelFixture {
    fn install_governance_fixture(
        &self,
        fixture: &GovernanceFixtureObject,
    ) -> Result<(), positron_kernel::CatalogFailure> {
        self.catalog.install_governance_fixture(fixture)
    }
}

fn establish_authority(
    volume: positron_kernel::OwnedPrimaryDataVolume,
    tenant: TenantId,
) -> Result<StorageKernelResourceAuthority, Box<dyn Error>> {
    let configuration = fixture_configuration(&volume, tenant, FixtureInventory::Declared)?;
    StorageKernelResourceAuthority::establish(volume, configuration)
        .map_err(|_| "kernel authority establishment failed".into())
}

#[derive(Clone, Copy)]
enum FixtureInventory {
    Declared,
    DetectedCpu(u64),
}

fn fixture_configuration(
    volume: &positron_kernel::OwnedPrimaryDataVolume,
    tenant: TenantId,
    detected_inventory: FixtureInventory,
) -> Result<ResourceGovernorConfiguration, Box<dyn Error>> {
    let cardinality = InventoryCardinalityLimits::new(1, 24)?;
    let large = ResourceAmounts::new([
        90_000_000, 4, 4, 90_000_000, 70_000, 4, 4, 4, 4, 16, 40_000_000,
    ]);
    let small = uniform(2);
    let durability = add(add(large, large)?, large)?;
    let recovery_capacity = add(add(add(durability, large)?, large)?, uniform(12))?;
    let ordinary_capacity = ResourceAmounts::new([
        8_000_000, 32, 32, 8_000_000, 2_048, 32, 32, 32, 4_096, 32, 2_000_000,
    ]);
    let raw = add(
        add(recovery_capacity, ordinary_capacity)?,
        cardinality.governor_bootstrap_overhead(1)?,
    )?;
    let detected = match detected_inventory {
        FixtureInventory::Declared => raw,
        FixtureInventory::DetectedCpu(cpu_work_units) => with_cpu(raw, cpu_work_units),
    };
    let disk = detected.get(ResourceDimension::DiskHeadroomBytes);
    let observed =
        ObservedResourceEnvironment::for_test(volume, detected, DiskObservation::new(disk))?;
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
            with_cpu(uniform(8), 1_024),
            with_cpu(uniform(6), 1_024),
            with_cpu(uniform(4), 1_024),
            uniform(2),
        )?,
    )?;
    let recovery =
        RecoveryPoolCapacities::new(durability, small, small, small, large, small, small)?;
    Ok(ResourceGovernorConfiguration::new(
        inventory, policy, recovery,
    )?)
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

#[test]
fn four_core_capacity_cannot_admit_the_declared_acknowledged_logs_fixture_quota()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoots::new("four-core-capacity")?;
    let volume = PrimaryDataVolume::acquire(&root.0, MountQualification::LocalHost)?;
    let failure = match fixture_configuration(
        &volume,
        TenantId::from_bytes([0xa1; 16])?,
        FixtureInventory::DetectedCpu(4_000),
    ) {
        Ok(_) => return Err("four logical CPUs unexpectedly admitted the fixture quota".into()),
        Err(failure) => failure,
    };

    assert_eq!(
        failure.downcast_ref::<GovernorFailure>(),
        Some(&GovernorFailure::InvalidConfiguration)
    );
    Ok(())
}

#[test]
fn acknowledged_logs_fixture_uses_its_declared_inventory_instead_of_live_host_capacity()
-> Result<(), Box<dyn Error>> {
    let _fixture = KernelFixture::new(
        TenantId::from_bytes([0xa2; 16])?,
        "deterministic-resource-inventory",
    )?;
    Ok(())
}
