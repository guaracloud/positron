#![no_main]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
    ResourceAmounts, ResourceDimension,
};
use positron_signals::{
    LogScan, LogStore, ScanCancellation, ScanLimit, ScanObservationFailureCode, ScanObserver,
    SchemaBudget, SchemaCatalog, TextSearchCandidate,
};

#[path = "schema_discovery_query/authority.rs"]
mod authority;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct NeverCancelled;

impl ScanCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct Unobserved;

impl ScanObserver for Unobserved {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_024 {
        return;
    }
    let tenant = TenantId::from_bytes([0x41; 16]).expect("tenant");
    let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("positron-query-search-{sequence}"));
    if fs::create_dir(&root).is_err() {
        return;
    }
    let outcome = run_once(data, tenant, &root);
    let _ = fs::remove_dir_all(root);
    if let Err(error) = outcome {
        panic!("physical matcher fuzz setup failed: {error}");
    }
});

fn run_once(
    data: &[u8],
    tenant: TenantId,
    root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = authority::establish(root, tenant)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x61; 16])?,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    let shard = VirtualShardId::new(61)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x64; 32])),
    )?;
    let mut body = String::from_utf8_lossy(data).into_owned();
    body.truncate(512);
    if data.first().is_none_or(|byte| byte & 1 == 0) {
        body.push_str(" needle ");
    }
    let has_match = body.contains("needle");
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let store = LogStore::new();
    let amounts = ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?;
    let capacity = authority
        .governor()
        .reserve(WorkClaim::tenant(tenant, WorkKind::Ingest, amounts)?)?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let identity = StoreBlockIdentity::new([0x65; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        capacity,
        &clock,
        tenant,
        shard,
        identity,
        vec![positron_signals::LogRecord::fuzz_text_body(body.clone())?],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    let snapshot = ledger.snapshot()?;
    let candidate = TextSearchCandidate::literal("needle")?
        .ok_or("literal candidate unexpectedly generic")?;
    let result = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &candidate,
        &NeverCancelled,
        &Unobserved,
    )?;
    assert_eq!(result.decoded_records() == 1, has_match);
    if has_match {
        assert_eq!(result.records().len(), 1);
    }
    Ok(())
}
