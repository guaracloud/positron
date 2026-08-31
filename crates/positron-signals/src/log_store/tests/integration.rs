use std::error::Error;
use std::num::NonZeroU64;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogPublicationFault,
    CatalogSecret, FixedLifecycleClockSource, FormatEpoch, InstanceId, LedgerCompletionState,
    LifecycleClock, MountQualification, OrdinaryPool, PreparedStoreBlock, PrimaryDataVolume,
    RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension,
    RetentionTimeAuthority, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
    SystemLifecycleClockSource, TransactionId, WorkClaim, WorkClass, WorkKind,
    with_catalog_generation_ambiguity_hook_after, with_catalog_publication_ambiguity_hook_after,
    with_catalog_publication_fault_after,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::{
    LogRecord, LogRetentionPolicy, LogScan, LogStore, ScanCancellation, ScanLimit,
    ScanObservationFailureCode, ScanObserver,
};

#[path = "support.rs"]
mod support;

use support::{TemporaryRoot, establish_kernel_authority, preparation_capacity};

#[path = "integration/retention_contract.rs"]
mod retention_contract;
#[path = "integration/retention_evidence.rs"]
mod retention_evidence;
#[path = "integration/retention_execution.rs"]
mod retention_execution;
#[path = "integration/retention_snapshots.rs"]
mod retention_snapshots;

struct CancelledRetention;

impl ScanCancellation for CancelledRetention {
    fn is_cancelled(&self) -> bool {
        true
    }
}

struct NeverCancelledRetention;

impl ScanCancellation for NeverCancelledRetention {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct RejectScannedBytes(ScanObservationFailureCode);

impl ScanObserver for RejectScannedBytes {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }

    fn observe_scanned_bytes(&self, _bytes: u64) -> Result<(), ScanObservationFailureCode> {
        Err(self.0)
    }
}

fn retention_clock() -> LifecycleClock<SystemLifecycleClockSource> {
    LifecycleClock::new(SystemLifecycleClockSource)
}

fn query_capacity_blocker_leaving<'kernel>(
    authority: &'kernel positron_kernel::StorageKernelResourceAuthority,
    tenant: TenantId,
    headroom: u64,
) -> Result<positron_kernel::ResourceReservation<'kernel>, Box<dyn Error>> {
    let snapshot = authority.governor().inspect()?;
    let dimension = ResourceDimension::MemoryBytes;
    let available = snapshot
        .pool_capacity(OrdinaryPool::Shared, dimension)
        .checked_sub(snapshot.pool_usage(OrdinaryPool::Shared, dimension))
        .and_then(|shared| {
            snapshot
                .pool_capacity(OrdinaryPool::InteractiveQueryTail, dimension)
                .checked_sub(snapshot.pool_usage(OrdinaryPool::InteractiveQueryTail, dimension))
                .and_then(|query| shared.checked_add(query))
        })
        .and_then(|available| available.checked_sub(headroom))
        .ok_or("query capacity blocker cannot leave requested headroom")?;
    Ok(authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::InteractiveQueryTail,
        ResourceAmounts::only(dimension, available)?,
    )?)?)
}

fn assert_same_resource_usage(
    before: &positron_kernel::ResourceSnapshot,
    after: &positron_kernel::ResourceSnapshot,
) {
    assert_eq!(after.outstanding_total(), before.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), before.usage(dimension));
    }
}

struct RetentionObserver;

impl ScanObserver for RetentionObserver {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}
