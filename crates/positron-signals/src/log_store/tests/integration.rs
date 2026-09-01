use std::error::Error;
use std::num::NonZeroU64;

use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_governance::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};
use positron_kernel::{
    ActiveSegmentLedger, AuditIntent, Catalog, CatalogObject, CatalogProposal,
    CatalogPublicationFault, CatalogSecret, FixedLifecycleClockSource, FormatEpoch, InstanceId,
    LedgerCompletionState, LifecycleClock, MountQualification, OrdinaryPool, PreparedStoreBlock,
    PrimaryDataVolume, RecoveryWorkClaim, RecoveryWorkKind, ResourceAmounts, ResourceDimension,
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

#[path = "integration/compaction.rs"]
mod compaction;
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

impl ScanObserver for NeverCancelledRetention {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
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

fn retention_policy(
    catalog: &Catalog<'_>,
    ledger: &ActiveSegmentLedger<'_, '_>,
    tenant: TenantId,
    seconds: u64,
) -> Result<LogRetentionPolicy, Box<dyn Error>> {
    let snapshot = catalog.pin()?;
    if let Ok(policy) = LogRetentionPolicy::from_catalog(&snapshot) {
        if policy.retention_seconds() != seconds {
            return Err("retention fixture policy mismatch".into());
        }
        return Ok(policy);
    }
    let intent = InitialTenantIntent::new(
        ledger.catalog_instance().to_bytes(),
        tenant,
        TenantSlug::parse_canonical("retention-test")?,
        "Retention test tenant",
        PrincipalId::from_bytes([0x11; 16])?,
        [0x21; 32],
        [0x22; 32],
        PrincipalId::from_bytes([0x12; 16])?,
        [0x23; 32],
        [0x24; 32],
        PrincipalId::from_bytes([0x13; 16])?,
        [0x25; 32],
        [0x26; 32],
        [0x27; 32],
        [0x28; 32],
        vec![0x29],
        vec![0x2a],
        seconds,
        1,
        1,
        [1; 11],
        InitialAuditContext::new(1, [0x2b; 16], true)?,
    )?;
    let (governance, audit) = InitialGovernanceIntent::create_tenant(intent)?.into_parts();
    let mut objects = snapshot
        .object_identities()
        .map(|identity| {
            CatalogObject::new(
                snapshot
                    .object(identity)?
                    .ok_or("Catalog fixture object disappeared")?
                    .to_vec(),
            )
            .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(CatalogObject::new(governance)?);
    let committed = catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0x2c; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        Some(AuditIntent::new(audit)?),
    )?;
    LogRetentionPolicy::from_catalog(committed.snapshot()).map_err(Into::into)
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
