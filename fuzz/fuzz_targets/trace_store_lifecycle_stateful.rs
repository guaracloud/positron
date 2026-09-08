#![no_main]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::{EventTime, SourceTimeQuality, UnixNanoseconds};
use positron_domain::value::ValueLimitProfile;
use positron_governance::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch,
    InstanceId, ResourceAmounts, ResourceDimension, RetentionTimeAuthority,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_policy::{
    IngestPolicy, NativeTraceCandidate, PolicyReceiver, TracePolicyEvaluation,
};
use positron_signals::{
    EvaluatedSpanObservationInput, SamplingDecision, ScanCancellation, ScanLimit,
    ScanObservationFailureCode, ScanObserver, SpanKind, SpanObservation, SpanObservationDetails,
    TraceRetentionPolicy, TraceScan, TraceStore, TraceStoreFailureCode,
};

#[path = "schema_discovery_query/authority.rs"]
mod authority;

const MAX_INPUT_BYTES: usize = 256;
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct FuzzRoot(PathBuf);

impl FuzzRoot {
    fn new() -> Option<Self> {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "positron-trace-lifecycle-fuzz-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).ok()?;
        Some(Self(root))
    }
}

impl Drop for FuzzRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct CancelAfterPolls {
    polls: AtomicU8,
    cancel_after: u8,
}

impl CancelAfterPolls {
    const fn new(cancel_after: u8) -> Self {
        Self {
            polls: AtomicU8::new(0),
            cancel_after,
        }
    }
}

impl ScanCancellation for CancelAfterPolls {
    fn is_cancelled(&self) -> bool {
        let polls = self.polls.fetch_add(1, Ordering::Relaxed);
        polls >= self.cancel_after
    }
}

struct Unobserved;

impl ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Some(root) = FuzzRoot::new() else {
        return;
    };
    if let Err(error) = run_once(data, &root.0) {
        panic!("public Trace Store lifecycle fuzz setup failed: {error:?}");
    }
});

fn run_once(data: &[u8], root: &Path) -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let authority = authority::establish_for_compaction(root, tenant)?;
    let instance = InstanceId::new([0x51; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x52; 32]), Box::new([0x53; 32])),
    )?;
    install_retention(&catalog, instance, tenant)?;
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(1_000_000_000),
    );
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(51)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x54; 32]));
    let store = TraceStore::new();

    // Two sealed segments are eligible for one fixed bucket; the third block
    // remains active and must stay outside copy-on-write compaction input.
    for marker in [0x61_u8, 0x62] {
        let sealed = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        append_observation(
            &sealed,
            &authority,
            &store,
            tenant,
            marker,
            data,
        )?;
        sealed.seal()?;
    }
    let active = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    append_observation(&active, &authority, &store, tenant, 0x63, data)?;

    let pinned_before = active.snapshot()?;
    let expected = observed_spans(&store, authority.governor(), tenant, &pinned_before)?;
    assert_eq!(expected.len(), 3, "fixture must expose sealed and active spans");
    let current_catalog = catalog.pin()?;
    let policy = TraceRetentionPolicy::from_catalog(&current_catalog)?;
    if pinned_before.blocks().is_empty() {
        return Err("missing sealed trace block".into());
    }
    let first_scan = observed_spans(&store, authority.governor(), tenant, &pinned_before)?;
    let first_span = first_scan.first().ok_or("missing trace observation")?;
    let bucket = policy.bucket(tenant, first_span.2)?;
    let prior_generation = catalog.pin()?.identity();

    let cancellation = CancelAfterPolls::new(data.first().copied().unwrap_or(2) & 0x03);
    let cancelled = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &cancellation,
            &Unobserved,
        )
        .expect_err("cancelled Trace compaction must reject before publication");
    assert_eq!(cancelled.code(), TraceStoreFailureCode::Cancelled);
    assert_eq!(
        catalog.pin()?.identity(),
        prior_generation
    );
    assert_eq!(
        active.snapshot()?.blocks().len(),
        pinned_before.blocks().len(),
        "rejected compaction must retain the existing manifest"
    );
    let publication_failure = positron_kernel::fuzz_compaction_publication_fault(true, || {
        store.compact(&active, tenant, policy, bucket)
    })
    .expect_err("publication failure must retain the Trace manifest");
    assert_eq!(publication_failure.code(), TraceStoreFailureCode::StorageUnavailable);
    assert_eq!(catalog.pin()?.identity(), prior_generation);
    assert_eq!(
        observed_spans(&store, authority.governor(), tenant, &active.snapshot()?)?,
        expected,
        "failed publication must not change visible observations"
    );

    let compacted = store.compact(&active, tenant, policy, bucket)?;
    assert_eq!((compacted.input_segments(), compacted.output_segments()), (2, 1));
    assert_eq!(compacted.input_blocks(), 2);
    assert_eq!(
        observed_spans(&store, authority.governor(), tenant, &active.snapshot()?)?,
        expected,
        "copy-on-write compaction must preserve current native visibility"
    );
    assert_eq!(
        observed_spans(&store, authority.governor(), tenant, &pinned_before)?,
        expected,
        "pinned snapshots must preserve pre-compaction visibility"
    );
    let repeated = store.compact(&active, tenant, policy, bucket)?;
    assert_eq!((repeated.input_segments(), repeated.output_segments()), (0, 0));

    // Retention acts on sealed ingest-time segments only. The active block is
    // still public after the old compacted output becomes unreachable.
    elapsed.advance(2_000_000_000)?;
    let before_retention = active.snapshot()?;
    let retention_generation = catalog.pin()?.identity();
    let retention_cancellation = CancelAfterPolls::new(1);
    let cancelled_retention = store
        .enforce_retention_observed(
            &active,
            tenant,
            TraceRetentionPolicy::from_catalog(&catalog.pin()?)?,
            &retention_cancellation,
            &Unobserved,
        )
        .expect_err("cancelled Trace retention must reject before publication");
    assert_eq!(cancelled_retention.code(), TraceStoreFailureCode::Cancelled);
    assert_eq!(catalog.pin()?.identity(), retention_generation);
    let retained = store.enforce_retention_observed(
        &active,
        tenant,
        TraceRetentionPolicy::from_catalog(&catalog.pin()?)?,
        &NeverCancelled,
        &Unobserved,
    )?;
    assert_eq!(retained.expired_segments(), 1);
    assert_eq!(
        observed_spans(&store, authority.governor(), tenant, &active.snapshot()?)?.len(),
        1,
        "retention must hide only the sealed compacted segment"
    );
    assert_eq!(
        observed_spans(&store, authority.governor(), tenant, &before_retention)?.len(),
        3,
        "pinned retention snapshots must retain prior visibility"
    );

    drop(before_retention);
    drop(pinned_before);
    drop(active);
    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    assert_eq!(
        observed_spans(&store, authority.governor(), tenant, &reopened.snapshot()?)?.len(),
        1,
        "restart must retain the published retention manifest"
    );
    drop(reopened);

    exercise_malformed_sealed_block(
        data,
        &authority,
        &retention_time,
        &catalog,
        tenant,
        &store,
    )
}

#[allow(clippy::too_many_arguments)]
fn exercise_malformed_sealed_block(
    data: &[u8],
    authority: &positron_kernel::StorageKernelResourceAuthority,
    retention_time: &RetentionTimeAuthority,
    catalog: &Catalog<'_>,
    tenant: TenantId,
    store: &TraceStore,
) -> Result<(), Box<dyn Error>> {
    let scope = SegmentScope::new(tenant, SignalKind::Traces, VirtualShardId::new(52)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x55; 32]));
    let policy = TraceRetentionPolicy::from_catalog(&catalog.pin()?)?;
    let corrupt = ActiveSegmentLedger::open_with_retention_time(
        authority,
        retention_time,
        catalog,
        scope,
        key(),
    )?;
    let preparation = corrupt.begin_store_block(capacity(authority, tenant)?, StoreBlockIdentity::new([0x71; 16])?)?;
    let bucket = policy.bucket(tenant, preparation.ingest_time())?;
    let mut malformed = legacy_v1_block(tenant, preparation.ingest_time().instant().value());
    malformed[0] ^= data.first().copied().unwrap_or(0).max(1);
    corrupt.append(preparation.finish(malformed)?)?;
    corrupt.seal()?;

    let valid = ActiveSegmentLedger::open_with_retention_time(
        authority,
        retention_time,
        catalog,
        scope,
        key(),
    )?;
    append_observation(&valid, authority, store, tenant, 0x72, data)?;
    valid.seal()?;
    let active = ActiveSegmentLedger::open_with_retention_time(
        authority,
        retention_time,
        catalog,
        scope,
        key(),
    )?;
    let before_generation = catalog.pin()?.identity();
    let before_blocks = active.snapshot()?.blocks().len();
    let rejected = store
        .compact_observed(
            &active,
            tenant,
            policy,
            bucket,
            &NeverCancelled,
            &Unobserved,
        )
        .expect_err("malformed native sealed block must not publish compaction");
    assert_eq!(rejected.code(), TraceStoreFailureCode::MalformedBlock);
    assert_eq!(catalog.pin()?.identity(), before_generation);
    assert_eq!(active.snapshot()?.blocks().len(), before_blocks);
    Ok(())
}

fn append_observation<'authority, 'catalog>(
    ledger: &ActiveSegmentLedger<'authority, 'catalog>,
    authority: &'authority positron_kernel::StorageKernelResourceAuthority,
    store: &TraceStore,
    tenant: TenantId,
    marker: u8,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    let name = format!(
        "trace-{marker:02x}-{:02x}",
        data.get(usize::from(marker) % data.len().max(1))
            .copied()
            .unwrap_or(marker)
    );
    let observation = observation(marker, name)?;
    let prepared = store.prepare(
        ledger.begin_store_block(capacity(authority, tenant)?, StoreBlockIdentity::new([marker; 16])?)?,
        vec![observation],
    )?;
    ledger.append(prepared.into_store_block())?;
    Ok(())
}

fn observed_spans(
    store: &TraceStore,
    governor: positron_kernel::ResourceGovernor<'_>,
    tenant: TenantId,
    snapshot: &positron_kernel::LedgerSnapshot<'_>,
) -> Result<Vec<([u8; 8], String, positron_kernel::IngestTime)>, Box<dyn Error>> {
    let scan = store.scan_physical(governor, tenant, snapshot, TraceScan::all(ScanLimit::new(8)?))?;
    Ok(scan
        .observations()
        .iter()
        .map(|span| {
            (
                span.observation().span_id(),
                span.observation().name().to_owned(),
                span.stored().ingest_time(),
            )
        })
        .collect())
}

fn observation(marker: u8, name: String) -> Result<SpanObservation, Box<dyn Error>> {
    let TracePolicyEvaluation::Accepted(evaluated) = IngestPolicy::preserving(1)?.evaluate_trace(
        NativeTraceCandidate::new(Vec::new()),
        PolicyReceiver::OtlpGrpc,
    )?
    else {
        return Err("preserving trace policy rejected fuzz observation".into());
    };
    Ok(SpanObservation::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        EvaluatedSpanObservationInput {
            trace_id: [0x66; 16],
            span_id: [marker; 8],
            parent_span_id: None,
            name,
            start_time: EventTime::received(UnixNanoseconds::new(i64::from(marker)), SourceTimeQuality::Usable)?,
            end_time: EventTime::missing(),
            kind: SpanKind::Server,
            sampling: SamplingDecision::Sampled,
            evaluated: *evaluated,
            details: SpanObservationDetails::default(),
        },
    )?)
}

fn capacity(
    authority: &positron_kernel::StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<positron_kernel::ResourceReservation<'_>, Box<dyn Error>> {
    Ok(authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?)
}

fn install_retention(
    catalog: &Catalog<'_>,
    instance: InstanceId,
    tenant: TenantId,
) -> Result<(), Box<dyn Error>> {
    let intent = InitialTenantIntent::new(
        instance.to_bytes(),
        tenant,
        positron_domain::identity::TenantSlug::parse_canonical("trace-fuzz")?,
        "Trace fuzz",
        positron_domain::identity::PrincipalId::from_bytes([0x81; 16])?,
        [0x82; 32],
        [0x83; 32],
        positron_domain::identity::PrincipalId::from_bytes([0x84; 16])?,
        [0x85; 32],
        [0x86; 32],
        positron_domain::identity::PrincipalId::from_bytes([0x87; 16])?,
        [0x88; 32],
        [0x89; 32],
        [0x8a; 32],
        [0x8b; 32],
        vec![1],
        vec![2],
        1,
        1,
        1,
        [1; 11],
        InitialAuditContext::new(1, [0x8c; 16], true)?,
    )?;
    let (governance, audit) = InitialGovernanceIntent::create_tenant(intent)?.into_parts();
    let basis = catalog.pin()?;
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            positron_kernel::TransactionId::new([0x8d; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance)?],
        )?,
        Some(positron_kernel::AuditIntent::new(audit)?),
    )?;
    Ok(())
}

fn legacy_v1_block(tenant: TenantId, ingest_time: i64) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(b"PTRCBL01");
    block.extend_from_slice(&1_u16.to_be_bytes());
    block.extend_from_slice(&tenant.to_bytes());
    block.extend_from_slice(&1_u16.to_be_bytes());
    block.extend_from_slice(&[0xa1; 16]);
    block.extend_from_slice(&[0xa2; 8]);
    block.push(0);
    block.push(2);
    block.push(1);
    block.push(2);
    block.push(2);
    block.extend_from_slice(&6_u32.to_be_bytes());
    block.extend_from_slice(b"legacy");
    block.extend_from_slice(&0_u16.to_be_bytes());
    block.extend_from_slice(&7_u64.to_be_bytes());
    block.extend_from_slice(&[0xa3; 32]);
    block.extend_from_slice(&0_u16.to_be_bytes());
    block.extend_from_slice(&ingest_time.to_be_bytes());
    block
}
