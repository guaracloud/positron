#![no_main]

use std::fs;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::{
    AttributeNamespace, CandidateAttributeValue, CandidateKeyValue, ValueLimitProfile,
};
use positron_governance::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogObject, CatalogProposal, CatalogSecret, FormatEpoch,
    InstanceId, ResourceAmounts, ResourceDimension, RetentionTimeAuthority,
    SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
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
    let authority = authority::establish(root, tenant)?;
    let instance = InstanceId::new([0x61; 16])?;
    let catalog = Catalog::open(
        &authority,
        instance,
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )?;
    install_policy(&catalog, instance, tenant)?;
    let retention_time = RetentionTimeAuthority::establish()?;
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

    for segment in 0_u8..2 {
        let ledger = ActiveSegmentLedger::open_with_retention_time(
            &authority,
            &retention_time,
            &catalog,
            scope,
            key(),
        )?;
        let identity = StoreBlockIdentity::new([segment.saturating_add(0x70); 16])?;
        let mut records = vec![fuzz_record(&ingest_policy, data, segment)?];
        let delta = schema.stage_group(&mut records)?;
        let block = store
            .prepare(
                ledger.begin_store_block(
                    ingest_capacity(&authority, tenant)?,
                    identity,
                )?,
                records,
            )?
            .into_store_block();
        let digest = block.content_digest()?;
        ledger.append(block)?;
        schema.commit(delta, identity, digest)?;
        if segment == 0 {
            let snapshot = ledger.snapshot()?;
            let block = snapshot
                .blocks()
                .iter()
                .find(|block| block.identity() == identity)
                .ok_or("missing first fuzz block")?;
            let path = SchemaPath::root(AttributeNamespace::Record, "fuzz.attribute".to_owned())?;
            let mut promotion = schema.stage_query_update()?;
            promotion.record_query_use(&path)?;
            promotion.index_replayed_query_path(tenant, &snapshot, block, &path)?;
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
        }
        ledger.seal()?;
    }

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
    let first = before.records().first().ok_or("missing fuzz record")?;
    let bucket = policy.bucket(tenant, first.ingest_time())?;
    let path = SchemaPath::root(AttributeNamespace::Record, "fuzz.attribute".to_owned())?;
    let second_identity = StoreBlockIdentity::new([0x71; 16])?;
    let second_block = before_snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == second_identity)
        .ok_or("missing second fuzz block")?;
    let mut re_promotion = schema.stage_query_update()?;
    re_promotion.record_query_use(&path)?;
    re_promotion.index_replayed_query_path(tenant, &before_snapshot, second_block, &path)?;
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
        assert_eq!(recovered.records().len(), 2);
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
    assert_eq!(restarted.records().len(), 2);
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
