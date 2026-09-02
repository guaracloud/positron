#![no_main]

use std::collections::BTreeSet;
use std::fs;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_governance::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch,
    InstanceId, ResourceAmounts, ResourceDimension, RetentionTimeAuthority,
    SegmentId, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_policy::{
    IngestPolicy, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation, PolicyReceiver,
};
use positron_signals::{
    LogMetadata, LogRecord, LogRetentionPolicy, LogScan, LogStore, ScanCancellation, ScanLimit,
    OccurrenceSelector, ScanObservationFailureCode, ScanObserver, SchemaBudget, SchemaPath,
    SchemaQuery, SchemaSessionStore, SchemaValue,
};

#[path = "schema_discovery_query/authority.rs"]
mod authority;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct InputCancellation(bool);

impl ScanCancellation for InputCancellation {
    fn is_cancelled(&self) -> bool {
        self.0
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
    let tenant = match TenantId::from_bytes([0x41; 16]) {
        Ok(tenant) => tenant,
        Err(_) => return,
    };
    let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("positron-log-compaction-{sequence}"));
    if fs::create_dir(&root).is_err() {
        return;
    }
    let result = run_once(data, tenant, &root);
    let _ = fs::remove_dir_all(root);
    if let Err(error) = result {
        panic!("public Log Store compaction fuzz setup failed: {error}");
    }
});

fn run_once(
    data: &[u8],
    tenant: TenantId,
    root: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = authority::establish_for_compaction(root, tenant)?;
    let instance = InstanceId::new([0x61; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    install_policy(&catalog, instance, tenant)?;
    const BUCKET_NANOS: u64 = 3_600_000_000_000;
    let (retention_time, elapsed) = RetentionTimeAuthority::establish_with_manual_elapsed(
        UnixNanoseconds::new(1_000_000_000),
    );
    let scope = SegmentScope::new(tenant, SignalKind::Logs, VirtualShardId::new(61)?);
    let key = || SegmentProtectionKey::from_owned(Box::new([0x64; 32]));
    let store = LogStore::new();
    let ingest_policy = IngestPolicy::preserving(7)?;
    let mut schema = SchemaSessionStore::new(
        ingest_capacity(&authority, tenant)?,
        tenant,
        SchemaBudget::new(1, 8_192, 512, 256)?,
    )?;
    let policy = LogRetentionPolicy::from_catalog(&catalog.pin()?)?;

    // The first sealed segment deliberately spans two fixed retention buckets.
    // It is never a compaction input: Log Store must select complete segments,
    // not individual blocks.
    let mixed = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let mixed_first = append_fuzz_block(
        &mixed,
        &authority,
        &store,
        &ingest_policy,
        &mut schema,
        data,
        0,
        0x70,
    )?;
    let snapshot = mixed.snapshot()?;
    let mixed_block = snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == mixed_first)
        .ok_or("missing mixed fuzz block")?;
    let path = SchemaPath::root(AttributeNamespace::Record, "fuzz.attribute".to_owned())?;
    let mut promotion = schema.stage_query_update()?;
    promotion.record_query_use(&path)?;
    promotion.index_replayed_query_path(tenant, &snapshot, mixed_block, &path)?;
    schema.commit_query_update(promotion)?;
    if !schema
        .catalog()
        .entry(&path)
        .is_some_and(positron_signals::SchemaEntry::promoted)
    {
        return Err("fuzz schema path was not promoted".into());
    }
    let mut demotion = schema.stage_query_update()?;
    demotion.remove_query_evidence(&path)?;
    schema.commit_query_update(demotion)?;
    if schema
        .catalog()
        .entry(&path)
        .is_some_and(positron_signals::SchemaEntry::promoted)
    {
        return Err("fuzz schema path did not demote".into());
    }
    drop(snapshot);
    elapsed.advance(BUCKET_NANOS)?;
    append_fuzz_block(
        &mixed,
        &authority,
        &store,
        &ingest_policy,
        &mut schema,
        data,
        1,
        0x71,
    )?;
    mixed.seal()?;

    // Two complete sealed segments share bucket one and are independently
    // eligible as a target. Two more share bucket two, while the final block
    // remains active. The input selects either target without selecting a
    // bucket from the first record's wall-clock timing.
    for (segment, marker) in [(2_u8, 0x72_u8), (3, 0x73)] {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        append_fuzz_block(
            &ledger,
            &authority,
            &store,
            &ingest_policy,
            &mut schema,
            data,
            segment,
            marker,
        )?;
        ledger.seal()?;
    }
    elapsed.advance(BUCKET_NANOS)?;
    for (segment, marker) in [(4_u8, 0x74_u8), (5, 0x75)] {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        append_fuzz_block(
            &ledger,
            &authority,
            &store,
            &ingest_policy,
            &mut schema,
            data,
            segment,
            marker,
        )?;
        ledger.seal()?;
    }
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    append_fuzz_block(
        &ledger,
        &authority,
        &store,
        &ingest_policy,
        &mut schema,
        data,
        6,
        0x76,
    )?;
    drop(ledger);

    let mut ledger = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let before_snapshot = ledger.snapshot()?;
    let before = store.scan(
        authority.governor(),
        tenant,
        &before_snapshot,
        LogScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(
        before.records().len(),
        7,
        "deterministic bucket fixture must expose every mixed, alternate, and active record"
    );
    let segment_for = |identity: StoreBlockIdentity| -> Result<SegmentId, Box<dyn std::error::Error>> {
        before_snapshot
            .blocks()
            .iter()
            .find(|block| block.identity() == identity)
            .map(|block| block.segment_id())
            .ok_or_else(|| format!("missing segment for fuzz block {identity:?}").into())
    };
    let mixed_segment = segment_for(StoreBlockIdentity::new([0x70; 16])?)?;
    assert_eq!(segment_for(StoreBlockIdentity::new([0x71; 16])?)?, mixed_segment);
    let bucket_one_segments = BTreeSet::from([
        segment_for(StoreBlockIdentity::new([0x72; 16])?)?,
        segment_for(StoreBlockIdentity::new([0x73; 16])?)?,
    ]);
    let bucket_two_segments = BTreeSet::from([
        segment_for(StoreBlockIdentity::new([0x74; 16])?)?,
        segment_for(StoreBlockIdentity::new([0x75; 16])?)?,
    ]);
    let target_selector = data.get(1).map_or(0, |byte| byte & 1);
    let target_record_index = if target_selector == 0 { 2 } else { 4 };
    let target_first = before
        .records()
        .get(target_record_index)
        .ok_or("missing selected target record")?;
    let bucket = policy.bucket(tenant, target_first.ingest_time())?;
    let target_identity = if target_selector == 0 {
        StoreBlockIdentity::new([0x72; 16])?
    } else {
        StoreBlockIdentity::new([0x74; 16])?
    };
    let target_segments = if target_selector == 0 {
        bucket_one_segments.clone()
    } else {
        bucket_two_segments.clone()
    };
    let target_block = before_snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == target_identity)
        .ok_or("missing selected target block")?;
    let mut re_promotion = schema.stage_query_update()?;
    re_promotion.record_query_use(&path)?;
    re_promotion.index_replayed_query_path(tenant, &before_snapshot, target_block, &path)?;
    schema.commit_query_update(re_promotion)?;
    if schema.catalog().overflow_record_count() == 0 {
        return Err("fuzz schema overflow was not retained".into());
    }
    let schema_query = SchemaQuery::value(
        path.clone(),
        OccurrenceSelector::Any,
        SchemaValue::signed_integer(0),
    );
    let schema_before = store.scan_schema(
        authority.governor(),
        tenant,
        &before_snapshot,
        LogScan::all(ScanLimit::new(8)?),
        schema.catalog(),
        &schema_query,
    )?;
    assert_eq!(schema_before.records().len(), 1);
    let expected_schema_records = schema_before.records().to_vec();
    let lease = ledger.create_snapshot_lease_for(0, NonZeroU64::new(60).ok_or("lease ttl")?)?;
    let leased_before = store.scan(
        authority.governor(),
        tenant,
        &lease.snapshot(),
        LogScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(leased_before.records().len(), before.records().len());
    let cancelled = InputCancellation(data.first().is_some_and(|byte| byte & 1 == 1));
    let fault_mode = data.first().map_or(0, |byte| (byte >> 1) % 3);
    let attempt = match fault_mode {
        1 => positron_kernel::fuzz_compaction_storage_fault(true, || {
            store.compact_observed(
                &ledger,
                tenant,
                policy,
                bucket,
                &cancelled,
                &Unobserved,
            )
        }),
        2 => positron_kernel::fuzz_compaction_publication_fault(true, || {
            store.compact_observed(
                &ledger,
                tenant,
                policy,
                bucket,
                &cancelled,
                &Unobserved,
            )
        }),
        _ => store.compact_observed(
            &ledger,
            tenant,
            policy,
            bucket,
            &cancelled,
            &Unobserved,
        ),
    };
    if cancelled.is_cancelled() {
        if attempt.is_ok() {
            return Err("cancelled public compaction unexpectedly succeeded".into());
        }
    } else if let Err(first_failure) = attempt {
        if fault_mode == 0 {
            return Err(first_failure.into());
        }
        drop(ledger);
        ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        let recovered = store.scan(
            authority.governor(),
            tenant,
            &ledger.snapshot()?,
            LogScan::all(ScanLimit::new(8)?),
        )?;
        assert_eq!(recovered.records().len(), 7);
        drop(recovered);
        store.compact(&ledger, tenant, policy, bucket)?;
    }
    if cancelled.is_cancelled() {
        store.compact(&ledger, tenant, policy, bucket)?;
    }
    let repeated = store.compact(&ledger, tenant, policy, bucket)?;
    assert_eq!(repeated.input_segments(), 0);
    assert_eq!(repeated.output_segments(), 0);
    let after = store.scan(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(8)?),
    )?;
    let after_snapshot = ledger.snapshot()?;
    let segment_for_after =
        |identity: StoreBlockIdentity| -> Result<SegmentId, Box<dyn std::error::Error>> {
            after_snapshot
                .blocks()
                .iter()
                .find(|block| block.identity() == identity)
                .map(|block| block.segment_id())
                .ok_or_else(|| format!("missing compacted fuzz block {identity:?}").into())
        };
    assert_eq!(
        segment_for_after(StoreBlockIdentity::new([0x70; 16])?)?,
        mixed_segment
    );
    assert_eq!(
        segment_for_after(StoreBlockIdentity::new([0x71; 16])?)?,
        mixed_segment
    );
    let target_markers = if target_selector == 0 {
        [0x72_u8, 0x73_u8]
    } else {
        [0x74_u8, 0x75_u8]
    };
    let target_output_segments = target_markers
        .into_iter()
        .map(|marker| segment_for_after(StoreBlockIdentity::new([marker; 16])?))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(target_output_segments.len(), 1);
    assert!(target_output_segments.is_disjoint(&target_segments));
    for marker in target_markers {
        let identity = StoreBlockIdentity::new([marker; 16])?;
        let output = after_snapshot
            .blocks()
            .iter()
            .find(|block| block.identity() == identity)
            .ok_or("missing target output block")?;
        let original = before
            .records()
            .iter()
            .find(|record| record.commit_position() == output.position())
            .ok_or("missing target source record")?;
        assert_eq!(policy.bucket(tenant, original.ingest_time())?, bucket);
    }
    let other_markers = if target_selector == 0 {
        [0x74_u8, 0x75_u8]
    } else {
        [0x72_u8, 0x73_u8]
    };
    for marker in other_markers {
        let identity = StoreBlockIdentity::new([marker; 16])?;
        assert_eq!(
            segment_for_after(identity)?,
            segment_for(identity)?
        );
    }
    let schema_after = store.scan_schema(
        authority.governor(),
        tenant,
        &after_snapshot,
        LogScan::all(ScanLimit::new(8)?),
        schema.catalog(),
        &schema_query,
    )?;
    assert_eq!(schema_after.records(), expected_schema_records.as_slice());
    assert!(schema_after.reduced_pruning());
    drop(after_snapshot);
    assert_eq!(
        before
            .records()
            .iter()
            .map(|record| (record.commit_position(), record.record_ordinal(), record.record().body()))
            .collect::<Vec<_>>(),
        after
            .records()
            .iter()
            .map(|record| (record.commit_position(), record.record_ordinal(), record.record().body()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        before
            .records()
            .iter()
            .map(|record| record.record())
            .collect::<Vec<_>>(),
        leased_before
            .records()
            .iter()
            .map(|record| record.record())
            .collect::<Vec<_>>()
    );
    drop(before_snapshot);
    drop(before);
    drop(schema_before);
    drop(schema_after);
    drop(leased_before);
    drop(lease);
    drop(after);
    drop(ledger);

    let reopened = ActiveSegmentLedger::open_with_retention_time(
        &authority,
        &retention_time,
        &catalog,
        scope,
        key(),
    )?;
    let restarted = store.scan(
        authority.governor(),
        tenant,
        &reopened.snapshot()?,
        LogScan::all(ScanLimit::new(8)?),
    )?;
    assert_eq!(restarted.records().len(), 7);
    let schema_encoding = schema.catalog().encode_catalog_object()?;
    let reopened_schema = positron_signals::SchemaCatalog::decode_catalog_object(&schema_encoding)?;
    let restarted_snapshot = reopened.snapshot()?;
    let restarted_schema = store.scan_schema(
        authority.governor(),
        tenant,
        &restarted_snapshot,
        LogScan::all(ScanLimit::new(8)?),
        &reopened_schema,
        &schema_query,
    )?;
    assert_eq!(restarted_schema.records(), expected_schema_records.as_slice());
    Ok(())
}

fn append_fuzz_block<'authority, 'catalog>(
    ledger: &ActiveSegmentLedger<'authority, 'catalog>,
    authority: &'authority positron_kernel::StorageKernelResourceAuthority,
    store: &LogStore,
    policy: &IngestPolicy,
    schema: &mut SchemaSessionStore,
    data: &[u8],
    segment: u8,
    marker: u8,
) -> Result<StoreBlockIdentity, Box<dyn std::error::Error>> {
    let identity = StoreBlockIdentity::new([marker; 16])?;
    let mut records = vec![fuzz_record(policy, data, segment)?];
    let delta = schema.stage_group(&mut records)?;
    let block = store
        .prepare(
            ledger.begin_store_block(ingest_capacity(authority, ledger.scope().tenant_id())?, identity)?,
            records,
        )?
        .into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    schema.commit(delta, identity, digest)?;
    Ok(identity)
}

fn fuzz_record(
    policy: &IngestPolicy,
    data: &[u8],
    segment: u8,
) -> Result<LogRecord, Box<dyn std::error::Error>> {
    let selector = data
        .get(usize::from(segment))
        .copied()
        .unwrap_or(segment)
        % 8;
    let mut body_bytes = data.to_vec();
    body_bytes.truncate(128);
    let body = match selector {
        0 => None,
        1 => Some(CandidateAttributeValue::null()),
        2 => Some(CandidateAttributeValue::boolean(segment % 2 == 0)),
        3 => Some(CandidateAttributeValue::signed_integer(i64::from(
            data.first().copied().unwrap_or(7),
        ))),
        4 => Some(CandidateAttributeValue::floating_point_bits(1.5_f64.to_bits())),
        5 => Some(CandidateAttributeValue::string(
            String::from_utf8_lossy(&body_bytes).into_owned(),
        )),
        6 => Some(CandidateAttributeValue::bytes(body_bytes)),
        _ => Some(CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "duplicate".to_owned(),
                CandidateAttributeValue::signed_integer(7),
            ),
            CandidateKeyValue::new(
                "duplicate".to_owned(),
                CandidateAttributeValue::string("replayed".to_owned()),
            ),
        ])),
    };
    let attributes = vec![
        NativeLogAttribute::new(
            AttributeNamespace::Record,
            "fuzz.attribute".to_owned(),
            vec![CandidateAttributeValue::signed_integer(i64::from(segment))],
        ),
        NativeLogAttribute::new(
            AttributeNamespace::Record,
            "fuzz.overflow".to_owned(),
            vec![CandidateAttributeValue::array(vec![CandidateAttributeValue::null()])],
        ),
    ];
    let candidate = NativeLogCandidate::new(
        Some(i64::from(segment)),
        (selector == 1).then_some(0),
        body,
        attributes,
        LogMetadata::new_with_event_name(
            i32::from(selector),
            "FUZZ".to_owned(),
            "compaction".to_owned(),
            None,
            None,
            0,
            0,
            0,
            "https://fuzz".to_owned(),
            "fuzz".to_owned(),
            "1".to_owned(),
            0,
            "https://fuzz".to_owned(),
        ),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving fuzz policy rejected a candidate".into());
    };
    Ok(LogRecord::checked_evaluated(
        ValueLimitProfile::release_1_system_maximum(),
        *evaluated,
    )?)
}

fn ingest_capacity<'authority>(
    authority: &'authority positron_kernel::StorageKernelResourceAuthority,
    tenant: TenantId,
) -> Result<positron_kernel::ResourceReservation<'authority>, Box<dyn std::error::Error>> {
    Ok(authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576)?,
    )?)?)
}

fn install_policy(
    catalog: &Catalog<'_>,
    instance: InstanceId,
    tenant: TenantId,
) -> Result<(), Box<dyn std::error::Error>> {
    let basis = catalog.pin()?;
    let (governance, audit) = InitialGovernanceIntent::create_tenant(InitialTenantIntent::new(
        instance.to_bytes(),
        tenant,
        positron_domain::identity::TenantSlug::parse_canonical("fuzz-tenant")?,
        "Fuzz tenant",
        positron_domain::identity::PrincipalId::from_bytes([0x11; 16])?,
        [0x21; 32],
        [0x22; 32],
        positron_domain::identity::PrincipalId::from_bytes([0x12; 16])?,
        [0x23; 32],
        [0x24; 32],
        positron_domain::identity::PrincipalId::from_bytes([0x13; 16])?,
        [0x25; 32],
        [0x26; 32],
        [0x27; 32],
        [0x28; 32],
        vec![0x29],
        vec![0x2a],
        3_600,
        1,
        1,
        [1; 11],
        InitialAuditContext::new(1, [0x2b; 16], true)?,
    )?)?
    .into_parts();
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            positron_kernel::TransactionId::new([0x2c; 16])?,
            FormatEpoch::CATALOG_V1,
            vec![CatalogObject::new(governance)?],
        )?,
        Some(positron_kernel::AuditIntent::new(audit)?),
    )?;
    Ok(())
}
