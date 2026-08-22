use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{CommitPosition, SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, AttributeValueKind,
    CandidateAttributeValue, CandidateKeyValue, NativeValueObserver,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LedgerSnapshot, LifecycleClock, MountQualification, PrimaryDataVolume, ResourceAmounts,
    ResourceDimension, ResourceGovernor, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
    WorkClaim, WorkKind,
};

use super::{LogRecord, LogScan, LogStore, PolicyProvenance, ScanLimit};
use crate::log_store::tests::support::{
    TemporaryRoot, establish_kernel_authority, preparation_capacity,
};
use crate::{
    LogScanResult, LogStoreFailure, LogStoreFailureCode, OccurrenceSelector, ScanCancellation,
    ScanObservationFailureCode, ScanObserver, SchemaBudget, SchemaCatalog, SchemaDiscoveryRequest,
    SchemaPath, SchemaQuery, SchemaSessionStore, SchemaValue, TextSearchCandidate,
};

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

struct RejectObservedWork;

impl ScanObserver for RejectObservedWork {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        if units > 0 {
            Err(ScanObservationFailureCode::BudgetExhausted)
        } else {
            Ok(())
        }
    }
}

#[test]
fn text_summary_prunes_absent_blocks_and_survives_reopen() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let kernel_catalog = Catalog::open(
        &authority,
        InstanceId::new([0x91; 16])?,
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(91)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &kernel_catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let identity = StoreBlockIdentity::new([0x95; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        vec![super::minimal_record("alpha βeta", 100)?],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    let snapshot = ledger.snapshot()?;
    let cancellation = NeverCancelled;
    let observer = Unobserved;

    let before_frontier = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::through(ScanLimit::new(1)?, CommitPosition::origin()),
        &schema,
        &TextSearchCandidate::literal("pha")?.ok_or("frontier candidate was generic")?,
        &cancellation,
        &observer,
    )?;
    assert!(before_frontier.records().is_empty());
    assert_eq!(before_frontier.scanned_bytes(), 0);

    let absent = TextSearchCandidate::literal("zzz")?
        .ok_or("absent literal candidate was unexpectedly generic")?;
    let other_schema = SchemaCatalog::new(
        TenantId::from_bytes([0x42; 16])?,
        SchemaBudget::release_1()?,
    )?;
    let scope_failure = store
        .scan_text_observed(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &other_schema,
            &absent,
            &cancellation,
            &observer,
        )
        .expect_err("a tenant-mismatched schema must be refused before scanning");
    assert_eq!(
        scope_failure.code(),
        LogStoreFailureCode::PhysicalScopeMismatch
    );
    let pruned = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &absent,
        &cancellation,
        &observer,
    )?;
    assert!(pruned.records().is_empty());
    assert_eq!(pruned.decoded_records(), 0);
    assert_eq!(pruned.scanned_bytes(), 0);
    assert!(!pruned.reduced_pruning());

    let present = TextSearchCandidate::literal("pha")?
        .ok_or("present literal candidate was unexpectedly generic")?;
    let decoded = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &present,
        &cancellation,
        &observer,
    )?;
    assert_eq!(decoded.records().len(), 1);
    assert_eq!(decoded.decoded_records(), 1);
    assert!(decoded.scanned_bytes() > 0);
    assert!(!decoded.reduced_pruning());

    // The ordinary catalog publication path and the checkpoint path must
    // account for the same version-3 text framing bytes.
    let catalog_object = schema.encode_catalog_object()?;
    let reopened_catalog = SchemaCatalog::decode_catalog_object(&catalog_object)?;
    assert_eq!(reopened_catalog.block_indexes, schema.block_indexes);

    let checkpoint = schema.encode_checkpoint_object(&[])?;
    let index_marker = checkpoint
        .windows(8)
        .position(|window| window == b"PINDEX1\0")
        .ok_or("text index marker missing")?;
    let text_presence = index_marker
        .checked_add(73)
        .ok_or("text presence offset overflow")?;
    let mut invalid_presence = checkpoint.clone();
    *invalid_presence
        .get_mut(text_presence)
        .ok_or("text presence missing")? = 2;
    assert!(SchemaCatalog::decode_checkpoint_object(&invalid_presence).is_err());
    let text_count = text_presence
        .checked_add(2)
        .ok_or("text count offset overflow")?;
    let mut oversized_summary = checkpoint.clone();
    oversized_summary
        .get_mut(text_count..text_count + 8)
        .ok_or("text count missing")?
        .copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(SchemaCatalog::decode_checkpoint_object(&oversized_summary).is_err());
    let reopened = SchemaCatalog::decode_checkpoint_object(&checkpoint)?.0;
    let reopened_pruned = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &reopened,
        &absent,
        &cancellation,
        &observer,
    )?;
    assert_eq!(reopened_pruned.records(), pruned.records());
    assert_eq!(reopened_pruned.scanned_bytes(), 0);
    assert!(!reopened_pruned.reduced_pruning());

    let budget_failure = store
        .scan_text_observed(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &reopened,
            &present,
            &cancellation,
            &RejectObservedWork,
        )
        .expect_err("text coverage work must be charged before digest/decode");
    assert_eq!(budget_failure.code(), LogStoreFailureCode::BudgetExhausted);

    let mut missing_summary = reopened;
    missing_summary
        .block_indexes
        .first_mut()
        .ok_or("text block index missing after reopen")?
        .text_summary = None;
    let fallback = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &missing_summary,
        &present,
        &cancellation,
        &observer,
    )?;
    assert_eq!(fallback.records(), decoded.records());
    assert!(fallback.scanned_bytes() > 0);
    assert!(fallback.reduced_pruning());

    let mut stale = SchemaCatalog::decode_checkpoint_object(&checkpoint)?.0;
    stale
        .block_indexes
        .first_mut()
        .ok_or("text block index missing for stale test")?
        .digest[0] ^= 1;
    let stale_result = store.scan_text_observed(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &stale,
        &present,
        &cancellation,
        &observer,
    )?;
    assert_eq!(stale_result.records(), decoded.records());
    assert!(stale_result.reduced_pruning());
    Ok(())
}

#[test]
fn stored_projection_compatibility_preserves_nested_occurrences_and_exact_matching()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x31; 16])?,
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(31)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x35; 32])),
    )?;
    let store = LogStore::new();
    let record = LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![
                CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                    "token".to_owned(),
                    CandidateAttributeValue::boolean(true),
                )]),
                CandidateAttributeValue::key_value_list(vec![CandidateKeyValue::new(
                    "token".to_owned(),
                    CandidateAttributeValue::signed_integer(7),
                )]),
            ],
        )],
        PolicyProvenance::new(1, [0x36; 32], vec![])?,
    )?;
    let prepared = store.prepare(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(10))),
        tenant,
        shard,
        StoreBlockIdentity::new([0x37; 16])?,
        vec![record],
    )?;
    ledger.append(prepared.into_store_block())?;
    let snapshot = ledger.snapshot()?;
    let scan = store.scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
    )?;
    let stored = scan
        .records()
        .first()
        .ok_or("stored fixture missing")?
        .stored();
    let path = SchemaPath::new(AttributeNamespace::Record, "payload.token".to_owned())?;

    let retained = stored
        .projected_attribute_retained_bytes(&path)?
        .ok_or("nested projection size missing")?;
    let projected = stored
        .project_attribute(&path)?
        .ok_or("nested projection missing")?;
    assert_eq!(projected.len(), 2);
    assert_eq!(
        projected.occurrence(0).and_then(|value| value.as_boolean()),
        Some(true)
    );
    assert_eq!(
        projected
            .occurrence(1)
            .and_then(|value| value.as_signed_integer()),
        Some(7)
    );

    let mut observer = ProjectionObserver::default();
    assert_eq!(
        stored
            .projected_attribute_retained_bytes_observed(&path, &mut observer)
            .expect("observed retained sizing succeeds"),
        Some(retained)
    );
    assert_eq!(
        stored
            .project_attribute_observed(&path, &mut observer)
            .expect("observed projection succeeds"),
        Some(projected)
    );
    assert!(observer.structures > 0);

    let matches = SchemaQuery::value(
        path,
        OccurrenceSelector::Any,
        SchemaValue::signed_integer(7),
    );
    assert!(matches.matches_stored_record(stored));
    let missing = SchemaPath::root(AttributeNamespace::Record, "missing".to_owned())?;
    assert_eq!(stored.projected_attribute_retained_bytes(&missing)?, None);
    assert_eq!(stored.project_attribute(&missing)?, None);
    Ok(())
}

#[derive(Default)]
struct ProjectionObserver {
    structures: usize,
}

impl NativeValueObserver for ProjectionObserver {
    type Error = ScanObservationFailureCode;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        self.structures += 1;
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn scalar_fallback_retains_its_vector_capacity_in_governed_stage_accounting()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let budget = SchemaBudget::new(8, 200_000, 1_000_000, 40_000)?;
    let base = u64::try_from(SchemaCatalog::base_memory_bound(budget)?)?;
    let reservation = authority.governor().reserve(WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, base)?,
    )?)?;
    let mut session = SchemaSessionStore::new(reservation, tenant, budget)?;
    let mut seed = vec![record_with_occurrences("indexed", &["seed", "seed-2"])?];
    let seed_delta = session.stage_group(&mut seed)?;
    session.commit(seed_delta, StoreBlockIdentity::new([0x46; 16])?, [0x47; 32])?;
    let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let mut query_update = session.stage_query_update()?;
    query_update.record_query_use(&path)?;
    session.commit_query_update(query_update)?;
    let mut promoted = vec![record_with_occurrences("indexed", &["promoted"])?];
    let promoted_delta = session.stage_group(&mut promoted)?;
    session.commit(
        promoted_delta,
        StoreBlockIdentity::new([0x48; 16])?,
        [0x49; 32],
    )?;
    let _cloned_update = session.stage_query_update()?;
    let first = (0..1_024)
        .map(|index| format!("first-{index:04}"))
        .collect::<Vec<_>>();
    let second = (0..1_024)
        .map(|index| format!("second-{index:04}"))
        .collect::<Vec<_>>();
    let mut records = vec![
        record_with_occurrences(
            "indexed",
            &first.iter().map(String::as_str).collect::<Vec<_>>(),
        )?,
        record_with_occurrences(
            "indexed",
            &second.iter().map(String::as_str).collect::<Vec<_>>(),
        )?,
    ];
    let delta = session.stage_group(&mut records)?;
    session.commit(delta, StoreBlockIdentity::new([0x4a; 16])?, [0x4b; 32])?;
    assert!(session.catalog().memory_bytes() <= budget.max_memory_bytes());
    Ok(())
}

#[test]
fn scalar_fallback_is_scoped_to_the_non_fitting_root() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x4a; 16])?,
        CatalogSecret::from_owned(Box::new([0x4b; 32]), Box::new([0x4c; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(21)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x4e; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(8, 200_000, 8_000, 8_000)?)?;
    for key in ["oversized", "kept"] {
        let seed = AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            key.to_owned(),
            vec![CandidateAttributeValue::string("seed".to_owned())],
        )
        .validate(LogStore::value_limit_profile())?;
        schema.observe(std::slice::from_ref(&seed))?;
        schema.record_query_use(&SchemaPath::root(
            AttributeNamespace::Record,
            key.to_owned(),
        )?)?;
    }
    let oversized = (0..512)
        .map(|index| CandidateAttributeValue::string(format!("oversized-{index:03}")))
        .collect::<Vec<_>>();
    let record = LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Record,
                "oversized".to_owned(),
                oversized,
            ),
            AttributeOccurrenceSetCandidate::new(
                AttributeNamespace::Record,
                "kept".to_owned(),
                vec![CandidateAttributeValue::string("kept".to_owned())],
            ),
        ],
        PolicyProvenance::new(1, [0x75; 32], vec![])?,
    )?;
    let second_record = record_with_occurrences("kept", &["kept-two"])?;
    let duplicate_record = record_with_occurrences("kept", &["kept"])?;
    let identity = StoreBlockIdentity::new([0x4f; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        vec![record, second_record, duplicate_record],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    let second_identity = StoreBlockIdentity::new([0x50; 16])?;
    let (second_prepared, second_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
        tenant,
        shard,
        second_identity,
        vec![record_with_occurrences("kept", &["kept-three"])?],
        &schema,
    )?;
    let second_block = second_prepared.into_store_block();
    let second_digest = second_block.content_digest()?;
    ledger.append(second_block)?;
    store.apply_schema_delta(&mut schema, second_delta, second_identity, second_digest)?;

    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &SchemaQuery::value(
            SchemaPath::root(AttributeNamespace::Record, "kept".to_owned())?,
            OccurrenceSelector::Any,
            SchemaValue::string("absent"),
        ),
    )?;
    assert!(result.records().is_empty());
    assert_eq!(result.scanned_bytes(), 0);
    assert!(!result.reduced_pruning());
    Ok(())
}

#[test]
fn merged_scalar_dictionary_falls_back_atomically_and_reopens() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let budget = SchemaBudget::new(8, 4_000_000, 1_048_576, 1_048_576)?;
    let mut schema = SchemaCatalog::new(tenant, budget)?;
    let store = LogStore::new();
    let nested_path = SchemaPath::new(AttributeNamespace::Record, "payload.token".to_owned())?;
    let kept_path = SchemaPath::root(AttributeNamespace::Record, "kept".to_owned())?;
    let seed = [
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "token".to_owned(),
                    CandidateAttributeValue::string("seed".to_owned()),
                ),
            ])],
        )
        .validate(LogStore::value_limit_profile())?,
        AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "kept".to_owned(),
            vec![CandidateAttributeValue::string("kept".to_owned())],
        )
        .validate(LogStore::value_limit_profile())?,
    ];
    schema.observe(&seed)?;
    schema.record_query_use(&nested_path)?;
    schema.record_query_use(&kept_path)?;

    let make_nested = |offset: usize, groups: &[usize]| -> Result<LogRecord, Box<dyn Error>> {
        let values = groups
            .iter()
            .copied()
            .enumerate()
            .map(|(group, count)| {
                CandidateAttributeValue::key_value_list(
                    (0..count)
                        .map(|index| {
                            CandidateKeyValue::new(
                                "token".to_owned(),
                                CandidateAttributeValue::signed_integer(
                                    (offset * 100_000 + group * 10_000 + index) as i64,
                                ),
                            )
                        })
                        .collect(),
                )
            })
            .collect();
        Ok(LogRecord::checked_receiver_candidate(
            LogStore::value_limit_profile(),
            None,
            None,
            Some(CandidateAttributeValue::string("body".to_owned())),
            vec![
                AttributeOccurrenceSetCandidate::new(
                    AttributeNamespace::Record,
                    "payload".to_owned(),
                    values,
                ),
                AttributeOccurrenceSetCandidate::new(
                    AttributeNamespace::Record,
                    "kept".to_owned(),
                    vec![CandidateAttributeValue::string("kept".to_owned())],
                ),
            ],
            PolicyProvenance::new(1, [0x56; 32], vec![])?,
        )?)
    };
    let mut records = vec![
        make_nested(0, &[1_024, 1_024, 1_024, 1_023])?,
        make_nested(1, &[2])?,
    ];
    let identity = StoreBlockIdentity::new([0x57; 16])?;
    let delta = store.stage_schema_group(&mut records, &schema)?;
    store.apply_schema_delta(&mut schema, delta, identity, [0x58; 32])?;
    let checkpoint = schema.encode_checkpoint_object(&[])?;
    let _reopened = SchemaCatalog::decode_checkpoint_object(&checkpoint)?.0;
    Ok(())
}

#[test]
fn scalar_budget_fallback_clears_prior_dictionary_values() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let kernel_catalog = Catalog::open(
        &authority,
        InstanceId::new([0x6b; 16])?,
        CatalogSecret::from_owned(Box::new([0x6c; 32]), Box::new([0x6d; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(27)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &kernel_catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x6e; 32])),
    )?;
    let store = LogStore::new();
    let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(8, 4_000_000, 1_048_576, 130)?)?;
    schema.observe(&[AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "indexed".to_owned(),
        vec![CandidateAttributeValue::string("a".to_owned())],
    )
    .validate(LogStore::value_limit_profile())?])?;
    schema.record_query_use(&path)?;
    let identity = StoreBlockIdentity::new([0x6f; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(106))),
        tenant,
        shard,
        identity,
        vec![record("indexed", "a")?, record("indexed", "b")?],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;

    let snapshot = ledger.snapshot()?;
    let query = SchemaQuery::value(
        path.clone(),
        OccurrenceSelector::Any,
        SchemaValue::string("b"),
    );
    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &query,
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(result.reduced_pruning());
    drop(result);
    let reopened =
        SchemaCatalog::decode_checkpoint_object(&schema.encode_checkpoint_object(&[])?)?.0;
    let reopened_result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &reopened,
        &query,
    )?;
    assert_eq!(reopened_result.records().len(), 1);
    assert!(reopened_result.reduced_pruning());
    Ok(())
}

#[test]
fn live_discovery_exhaustion_invalidates_unseen_promoted_descendants() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let kernel_catalog = Catalog::open(
        &authority,
        InstanceId::new([0x66; 16])?,
        CatalogSecret::from_owned(Box::new([0x67; 32]), Box::new([0x68; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(26)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &kernel_catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x69; 32])),
    )?;
    let store = LogStore::new();
    let path = SchemaPath::new(AttributeNamespace::Record, "payload.token".to_owned())?;
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    schema.observe(&[AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "payload".to_owned(),
        vec![CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "token".to_owned(),
                CandidateAttributeValue::signed_integer(0),
            ),
        ])],
    )
    .validate(LogStore::value_limit_profile())?])?;
    schema.record_query_use(&path)?;

    let first = nested_integer_record(vec![vec![CandidateKeyValue::new(
        "token".to_owned(),
        CandidateAttributeValue::signed_integer(0),
    )]])?;
    let mut noisy_values = Vec::new();
    for _ in 0..4 {
        let mut noisy_entries = Vec::new();
        for _ in 0..1_024 {
            noisy_entries.push(CandidateKeyValue::new(
                "noise".to_owned(),
                CandidateAttributeValue::signed_integer(1),
            ));
        }
        noisy_values.push(CandidateAttributeValue::key_value_list(noisy_entries));
    }
    let noisy = LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "noise".to_owned(),
            noisy_values,
        )],
        PolicyProvenance::new(1, [0x72; 32], vec![])?,
    )?;
    let second = LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "token".to_owned(),
                    CandidateAttributeValue::signed_integer(4_096),
                ),
            ])],
        )],
        PolicyProvenance::new(1, [0x73; 32], vec![])?,
    )?;
    let first_identity = StoreBlockIdentity::new([0x6a; 16])?;
    let (first_prepared, first_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
        tenant,
        shard,
        first_identity,
        vec![first],
        &schema,
    )?;
    let first_block = first_prepared.into_store_block();
    let first_digest = first_block.content_digest()?;
    ledger.append(first_block)?;
    store.apply_schema_delta(&mut schema, first_delta, first_identity, first_digest)?;

    let identity = StoreBlockIdentity::new([0x6b; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(105))),
        tenant,
        shard,
        identity,
        vec![noisy, second],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;

    let snapshot = ledger.snapshot()?;
    let query = SchemaQuery::value(
        path.clone(),
        OccurrenceSelector::Any,
        SchemaValue::signed_integer(4_096),
    );
    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &query,
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(result.reduced_pruning());
    drop(result);
    let reopened =
        SchemaCatalog::decode_checkpoint_object(&schema.encode_checkpoint_object(&[])?)?.0;
    let reopened_result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &reopened,
        &query,
    )?;
    assert_eq!(reopened_result.records().len(), 1);
    assert!(reopened_result.reduced_pruning());
    Ok(())
}

#[test]
fn governed_promotion_overflow_releases_sidecar_cost_and_reopens() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let kernel_catalog = Catalog::open(
        &authority,
        InstanceId::new([0x59; 16])?,
        CatalogSecret::from_owned(Box::new([0x5a; 32]), Box::new([0x5b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(24)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &kernel_catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )?;
    let store = LogStore::new();
    let path = SchemaPath::root(AttributeNamespace::Record, "scalar".to_owned())?;
    let identity = StoreBlockIdentity::new([0x5d; 16])?;
    let prepared = store
        .prepare(
            preparation_capacity(&authority, tenant)?,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(103))),
            tenant,
            shard,
            identity,
            vec![signed_record("scalar", 4_096)?],
        )?
        .into_store_block();
    let digest = prepared.content_digest()?;
    ledger.append(prepared)?;
    let snapshot = ledger.snapshot()?;

    let mut fixture = SchemaCatalog::new(
        tenant,
        SchemaBudget::new(8, 16_000_000, 1_048_576, 16_000_000)?,
    )?;
    fixture.observe(&[AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "scalar".to_owned(),
        vec![CandidateAttributeValue::signed_integer(0)],
    )
    .validate(LogStore::value_limit_profile())?])?;
    fixture.record_query_use(&path)?;
    let values = (0..4_096)
        .map(SchemaValue::signed_integer)
        .collect::<Vec<_>>();
    let full = crate::log_store::schema::SchemaIndexPath::from_variants_and_values(
        &path,
        &[AttributeValueKind::SignedInteger],
        &values,
    )?;
    fixture.install_query_index(crate::log_store::schema::SchemaBlockIndex::one(
        identity, digest, full,
    )?)?;
    let full_index_bytes = fixture.index_bytes();
    let checkpoint = fixture.encode_checkpoint_object(&[])?;
    let (mut session, _) = SchemaSessionStore::from_checkpoint(
        preparation_capacity(&authority, tenant)?,
        tenant,
        &checkpoint,
    )?
    .ok_or("checkpoint tenant")?;

    let mut update = session.stage_query_update()?;
    update.index_replayed_query_path(
        tenant,
        &snapshot,
        snapshot.blocks().first().ok_or("replayed block")?,
        &path,
    )?;
    session.commit_query_update(update)?;
    assert!(session.catalog().index_bytes() < full_index_bytes);

    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        session.catalog(),
        &SchemaQuery::value(
            path.clone(),
            OccurrenceSelector::Any,
            SchemaValue::signed_integer(4_096),
        ),
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(result.reduced_pruning());

    let reopened =
        SchemaCatalog::decode_checkpoint_object(&session.catalog().encode_checkpoint_object(&[])?)?
            .0;
    assert_eq!(reopened.index_bytes(), session.catalog().index_bytes());
    Ok(())
}

#[test]
fn scalar_index_prunes_an_absent_same_type_value() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1b; 16])?,
        CatalogSecret::from_owned(Box::new([0x2b; 32]), Box::new([0x3b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(11)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x5b; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let indexed_path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let seed = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "indexed".to_owned(),
        vec![CandidateAttributeValue::string("one".to_owned())],
    )
    .validate(LogStore::value_limit_profile())?;
    schema.observe(&[seed])?;
    schema.record_query_use(&indexed_path)?;
    let identity = StoreBlockIdentity::new([0x6b; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        vec![record("indexed", "one")?],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;

    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &query("indexed", "two")?,
    )?;
    assert!(result.records().is_empty());
    assert_eq!(result.scanned_bytes(), 0);
    assert!(!result.reduced_pruning());
    Ok(())
}

#[test]
fn scalar_index_prunes_an_absent_nested_value() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1c; 16])?,
        CatalogSecret::from_owned(Box::new([0x2c; 32]), Box::new([0x3c; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(12)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x5c; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let seed = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "payload".to_owned(),
        vec![CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "token".to_owned(),
                CandidateAttributeValue::string("one".to_owned()),
            ),
        ])],
    )
    .validate(LogStore::value_limit_profile())?;
    schema.observe(std::slice::from_ref(&seed))?;
    let nested_path = SchemaPath::new(AttributeNamespace::Record, "payload.token".to_owned())?;
    schema.record_query_use(&nested_path)?;
    let identity = StoreBlockIdentity::new([0x6c; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        vec![nested_record("one")?],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;

    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &SchemaQuery::value(
            nested_path,
            OccurrenceSelector::Any,
            SchemaValue::string("two"),
        ),
    )?;
    assert!(result.records().is_empty());
    assert_eq!(result.scanned_bytes(), 0);
    assert!(!result.reduced_pruning());
    Ok(())
}

#[test]
fn scalar_index_round_trips_each_native_scalar_dictionary() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1d; 16])?,
        CatalogSecret::from_owned(Box::new([0x2d; 32]), Box::new([0x3d; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(13)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x5d; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let values = vec![
        (
            "null",
            CandidateAttributeValue::null(),
            SchemaValue::null(),
            SchemaValue::kind(AttributeValueKind::Boolean),
        ),
        (
            "boolean",
            CandidateAttributeValue::boolean(true),
            SchemaValue::boolean(true),
            SchemaValue::boolean(false),
        ),
        (
            "boolean_false",
            CandidateAttributeValue::boolean(false),
            SchemaValue::boolean(false),
            SchemaValue::boolean(true),
        ),
        (
            "integer",
            CandidateAttributeValue::signed_integer(7),
            SchemaValue::signed_integer(7),
            SchemaValue::signed_integer(8),
        ),
        (
            "floating",
            CandidateAttributeValue::floating_point_bits(1.5_f64.to_bits()),
            SchemaValue::floating_point_bits(1.5_f64.to_bits()),
            SchemaValue::floating_point_bits(2.5_f64.to_bits()),
        ),
        (
            "string",
            CandidateAttributeValue::string("one".to_owned()),
            SchemaValue::string("one"),
            SchemaValue::string("two"),
        ),
        (
            "bytes",
            CandidateAttributeValue::bytes(vec![1, 2]),
            SchemaValue::bytes(vec![1, 2]),
            SchemaValue::bytes(vec![2, 1]),
        ),
    ];
    let mut records = Vec::new();
    for (key, candidate, _, _) in &values {
        let seed = AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            (*key).to_owned(),
            vec![candidate.clone()],
        )
        .validate(LogStore::value_limit_profile())?;
        schema.observe(std::slice::from_ref(&seed))?;
        schema.record_query_use(&SchemaPath::root(
            AttributeNamespace::Record,
            (*key).to_owned(),
        )?)?;
        records.push(scalar_record(key, candidate.clone())?);
    }
    for (namespace, key) in [
        (AttributeNamespace::Stream, "stream_id"),
        (AttributeNamespace::Resource, "resource_id"),
        (AttributeNamespace::InstrumentationScope, "scope_id"),
    ] {
        let candidate = CandidateAttributeValue::signed_integer(7);
        let seed = AttributeOccurrenceSetCandidate::new(
            namespace,
            key.to_owned(),
            vec![candidate.clone()],
        )
        .validate(LogStore::value_limit_profile())?;
        schema.observe(std::slice::from_ref(&seed))?;
        schema.record_query_use(&SchemaPath::root(namespace, key.to_owned())?)?;
        records.push(scalar_record_in_namespace(namespace, key, candidate)?);
    }
    let identity = StoreBlockIdentity::new([0x6d; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        records,
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    let encoded = schema
        .encode_catalog_object()
        .map_err(|failure| format!("encode: {failure:?}"))?;
    let reopened = SchemaCatalog::decode_catalog_object(&encoded)
        .map_err(|failure| format!("decode: {failure:?}"))?;
    let snapshot = ledger.snapshot()?;
    for (key, _, expected, absent) in values {
        let path = SchemaPath::root(AttributeNamespace::Record, key.to_owned())?;
        let present = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &reopened,
            &SchemaQuery::value(path.clone(), OccurrenceSelector::Any, expected),
        )?;
        assert_eq!(present.records().len(), 1, "present value for {key}");
        assert!(!present.reduced_pruning());
        let missing = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &reopened,
            &SchemaQuery::value(path, OccurrenceSelector::Any, absent),
        )?;
        assert!(missing.records().is_empty(), "absent value for {key}");
        assert_eq!(missing.scanned_bytes(), 0, "pruned value for {key}");
        assert!(!missing.reduced_pruning());
    }
    for (namespace, key) in [
        (AttributeNamespace::Stream, "stream_id"),
        (AttributeNamespace::Resource, "resource_id"),
        (AttributeNamespace::InstrumentationScope, "scope_id"),
    ] {
        let path = SchemaPath::root(namespace, key.to_owned())?;
        let present = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &reopened,
            &SchemaQuery::value(
                path.clone(),
                OccurrenceSelector::Any,
                SchemaValue::signed_integer(7),
            ),
        )?;
        assert_eq!(present.records().len(), 1);
        assert!(!present.reduced_pruning());
        let absent = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &reopened,
            &SchemaQuery::value(
                path,
                OccurrenceSelector::Any,
                SchemaValue::signed_integer(8),
            ),
        )?;
        assert!(absent.records().is_empty());
        assert_eq!(absent.scanned_bytes(), 0);
        assert!(!absent.reduced_pruning());
    }
    Ok(())
}

#[test]
fn public_schema_scan_filters_durable_generic_and_overflow_records() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x19; 16])?,
        CatalogSecret::from_owned(Box::new([0x29; 32]), Box::new([0x39; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(9)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(1, 8_192, 8_192, 256)?)?;
    let seed = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "indexed".to_owned(),
        vec![CandidateAttributeValue::string("one".to_owned())],
    )
    .validate(LogStore::value_limit_profile())?;
    schema.observe(std::slice::from_ref(&seed))?;
    schema.record_query_use(&SchemaPath::root(
        AttributeNamespace::Record,
        "indexed".to_owned(),
    )?)?;
    let records = vec![
        record_with_occurrences("indexed", &["one", "two", "one"])?,
        record("indexed", "three")?,
        record("overflow", "two")?,
    ];
    let identity = StoreBlockIdentity::new([0x69; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        records,
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    let _sealed = ledger.seal()?;
    let successor = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )?;
    let checkpoint = schema.encode_catalog_object()?;
    let reopened = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    let original_discovery = reopened.discover(SchemaDiscoveryRequest::new(1, 0)?)?;
    let marker = checkpoint
        .windows(8)
        .position(|window| window == b"PVALUES\0")
        .ok_or("scalar dictionary")?;
    let value_offset = checkpoint
        .get(marker + 8..)
        .and_then(|bytes| bytes.windows(3).position(|window| window == b"one"))
        .and_then(|offset| marker.checked_add(8)?.checked_add(offset))
        .ok_or("scalar value")?;
    let mut changed_checkpoint = checkpoint.clone();
    changed_checkpoint[value_offset..value_offset + 3].copy_from_slice(b"odd");
    let changed = SchemaCatalog::decode_catalog_object(&changed_checkpoint)?;
    let changed_discovery = changed.discover(SchemaDiscoveryRequest::new(1, 0)?)?;
    assert_ne!(
        original_discovery.snapshot_digest(),
        changed_discovery.snapshot_digest(),
        "authenticated discovery digest must include scalar dictionary contents"
    );
    let snapshot = successor.snapshot()?;
    let presence = marker.checked_sub(1).ok_or("presence byte")?;
    let mut stale_checkpoint = checkpoint.clone();
    stale_checkpoint[presence] = 0;
    stale_checkpoint.truncate(presence + 1);
    let (mut replayed, _) = SchemaSessionStore::from_checkpoint(
        preparation_capacity(&authority, tenant)?,
        tenant,
        &stale_checkpoint,
    )?
    .ok_or("checkpoint tenant")?;
    let target = snapshot.blocks().first().ok_or("target block")?;
    let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let mut query_update = replayed.stage_query_update()?;
    query_update.index_replayed_query_path(tenant, &snapshot, target, &path)?;
    replayed.commit_query_update(query_update)?;
    let mut repeated_update = replayed.stage_query_update()?;
    repeated_update.index_replayed_query_path(tenant, &snapshot, target, &path)?;
    replayed.commit_query_update(repeated_update)?;

    let indexed = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        replayed.catalog(),
        &query("indexed", "one")?,
    )?;
    assert_eq!(indexed.records().len(), 1);
    assert!(!indexed.reduced_pruning());
    let indexed_record = indexed.records()[0].record().clone();
    let indexed_reduced = indexed.reduced_pruning();
    replayed.retain_reachable_indexes(&[(target.identity(), target.content_digest()?)])?;
    replayed.reconcile_block_identity(target.identity(), [0x72; 32])?;
    let mut demotion = replayed.stage_query_update()?;
    demotion.remove_query_evidence(&path)?;
    replayed.commit_query_update(demotion)?;
    replayed.reconcile_block_identity(StoreBlockIdentity::new([0x70; 16])?, [0x71; 32])?;
    for (selector, expected_match) in [
        (OccurrenceSelector::Index(0), true),
        (OccurrenceSelector::Index(1), true),
        (OccurrenceSelector::Index(2), true),
        (OccurrenceSelector::All, false),
    ] {
        let expected = if matches!(selector, OccurrenceSelector::Index(1)) {
            "two"
        } else {
            "one"
        };
        let ordered = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(2)?),
            &schema,
            &SchemaQuery::value(
                SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?,
                selector,
                SchemaValue::string(expected),
            ),
        )?;
        assert_eq!(ordered.records().len() == 1, expected_match);
    }
    let indexed_reopened = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &reopened,
        &query("indexed", "one")?,
    )?;
    assert_eq!(indexed_reopened.records(), indexed.records());
    assert_eq!(
        indexed_reopened.reduced_pruning(),
        indexed.reduced_pruning()
    );
    let mut stale_digest = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    stale_digest.block_indexes[0].digest[0] ^= 1;
    let stale = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(3)?),
        &stale_digest,
        &query("indexed", "one")?,
    )?;
    assert_eq!(stale.records(), indexed.records());
    assert!(stale.reduced_pruning());

    let mut replacement_identity = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    replacement_identity.block_indexes[0].identity = StoreBlockIdentity::new([0x7a; 16])?;
    let replacement = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(3)?),
        &replacement_identity,
        &query("indexed", "one")?,
    )?;
    assert_eq!(replacement.records(), indexed.records());
    assert!(replacement.reduced_pruning());

    let mut forged_kinds = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    forged_kinds.block_indexes[0].paths[0].kind_mask = 1 << 1;
    let forged = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(3)?),
        &forged_kinds,
        &query("indexed", "one")?,
    )?;
    assert_eq!(forged.records(), indexed.records());
    assert!(forged.reduced_pruning());

    let generic = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let demoted = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(3)?),
        &generic,
        &query("indexed", "one")?,
    )?;
    assert_eq!(demoted.records(), indexed.records());
    assert!(demoted.reduced_pruning());
    let pruned = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &SchemaQuery::value(
            SchemaPath::new(AttributeNamespace::Record, "indexed".to_owned())?,
            OccurrenceSelector::Any,
            SchemaValue::signed_integer(1),
        ),
    )?;
    assert!(pruned.records().is_empty());
    assert_eq!(pruned.scanned_bytes(), 0);
    assert!(!pruned.reduced_pruning());

    for value in [
        SchemaValue::null(),
        SchemaValue::boolean(true),
        SchemaValue::floating_point_bits(1.0_f64.to_bits()),
        SchemaValue::bytes(vec![1]),
    ] {
        let other_type = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(2)?),
            &schema,
            &SchemaQuery::value(
                SchemaPath::new(AttributeNamespace::Record, "indexed".to_owned())?,
                OccurrenceSelector::Any,
                value,
            ),
        )?;
        assert!(other_type.records().is_empty());
        assert_eq!(other_type.scanned_bytes(), 0);
        assert!(!other_type.reduced_pruning());
    }
    for value in [
        SchemaValue::kind(AttributeValueKind::Array),
        SchemaValue::kind(AttributeValueKind::KeyValueList),
    ] {
        let composite = observed_schema_scan(
            &store,
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(3)?),
            &schema,
            &SchemaQuery::value(
                SchemaPath::new(AttributeNamespace::Record, "indexed".to_owned())?,
                OccurrenceSelector::Any,
                value,
            ),
        )?;
        assert!(composite.records().is_empty());
        assert!(composite.scanned_bytes() > 0);
        assert!(composite.reduced_pruning());
    }
    for (kind, expected_records, expected_scanned) in [
        (AttributeValueKind::Null, 0, 0),
        (AttributeValueKind::Boolean, 0, 0),
        (AttributeValueKind::SignedInteger, 0, 0),
        (AttributeValueKind::FloatingPoint, 0, 0),
        (AttributeValueKind::String, 2, 1),
        (AttributeValueKind::Bytes, 0, 0),
    ] {
        let typed = store.scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(2)?),
            &schema,
            &SchemaQuery::value(
                SchemaPath::new(AttributeNamespace::Record, "indexed".to_owned())?,
                OccurrenceSelector::Any,
                SchemaValue::kind(kind),
            ),
        )?;
        assert_eq!(typed.records().len(), expected_records);
        assert_eq!(typed.scanned_bytes() > 0, expected_scanned == 1);
    }

    let overflow = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(3)?),
        &schema,
        &query("overflow", "two")?,
    )?;
    assert_eq!(overflow.records().len(), 1);
    assert!(overflow.reduced_pruning());
    let overflow_reopened = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(3)?),
        &reopened,
        &query("overflow", "two")?,
    )?;
    assert_eq!(overflow_reopened.records(), overflow.records());
    assert_eq!(
        overflow_reopened.reduced_pruning(),
        overflow.reduced_pruning()
    );

    // This is a canonical rewritten sealed-block fixture, not a compaction
    // executor: it proves representation invariance through public prepare,
    // seal, reopen, and scan behavior.
    drop(indexed);
    drop(indexed_reopened);
    drop(stale);
    drop(replacement);
    drop(forged);
    drop(demoted);
    drop(pruned);
    drop(overflow);
    drop(overflow_reopened);
    drop(replayed);
    drop(snapshot);
    drop(successor);
    let canonical_shard = VirtualShardId::new(23)?;
    let canonical_scope = SegmentScope::new(tenant, SignalKind::Logs, canonical_shard);
    let canonical_ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        canonical_scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let mut canonical_schema =
        SchemaCatalog::new(tenant, SchemaBudget::new(1, 8_192, 8_192, 256)?)?;
    canonical_schema.observe(std::slice::from_ref(&seed))?;
    canonical_schema.record_query_use(&path)?;
    let canonical_identity = StoreBlockIdentity::new([0x7a; 16])?;
    let (canonical, canonical_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(102))),
        tenant,
        canonical_shard,
        canonical_identity,
        vec![record_with_occurrences("indexed", &["one", "two", "one"])?],
        &canonical_schema,
    )?;
    let canonical_block = canonical.into_store_block();
    let canonical_digest = canonical_block.content_digest()?;
    canonical_ledger.append(canonical_block)?;
    store.apply_schema_delta(
        &mut canonical_schema,
        canonical_delta,
        canonical_identity,
        canonical_digest,
    )?;
    let _canonical_sealed = canonical_ledger.seal()?;
    let canonical_reopened = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        canonical_scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let compacted = store.scan_schema(
        authority.governor(),
        tenant,
        &canonical_reopened.snapshot()?,
        LogScan::all(ScanLimit::new(2)?),
        &canonical_schema,
        &query("indexed", "one")?,
    )?;
    assert_eq!(compacted.records().len(), 1);
    assert_eq!(
        compacted.records()[0].record(),
        &indexed_record,
        "canonical rewritten sealed block changed logical records"
    );
    assert_eq!(
        compacted.reduced_pruning(),
        indexed_reduced,
        "canonical rewritten sealed block changed pruning metadata"
    );
    Ok(())
}

#[test]
fn scalar_index_falls_back_for_a_composite_block() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1e; 16])?,
        CatalogSecret::from_owned(Box::new([0x2e; 32]), Box::new([0x3e; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(14)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x5e; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let seed = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "indexed".to_owned(),
        vec![CandidateAttributeValue::string("one".to_owned())],
    )
    .validate(LogStore::value_limit_profile())?;
    schema.observe(std::slice::from_ref(&seed))?;
    schema.record_query_use(&path)?;

    for (identity, record) in [
        (
            StoreBlockIdentity::new([0x6e; 16])?,
            record("indexed", "one")?,
        ),
        (
            StoreBlockIdentity::new([0x6f; 16])?,
            array_record("indexed")?,
        ),
    ] {
        let (prepared, delta) = store.prepare_with_schema_delta(
            preparation_capacity(&authority, tenant)?,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
            tenant,
            shard,
            identity,
            vec![record],
            &schema,
        )?;
        let block = prepared.into_store_block();
        let digest = block.content_digest()?;
        ledger.append(block)?;
        store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    }

    let snapshot = ledger.snapshot()?;
    let present = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &query("indexed", "one")?,
    )?;
    assert_eq!(present.records().len(), 1);
    assert!(present.reduced_pruning());
    let absent = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &query("indexed", "two")?,
    )?;
    assert!(absent.records().is_empty());
    assert!(absent.scanned_bytes() > 0);
    assert!(absent.reduced_pruning());
    Ok(())
}

#[test]
fn public_schema_scan_honors_scope_frontier_and_result_bounds() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1a; 16])?,
        CatalogSecret::from_owned(Box::new([0x2a; 32]), Box::new([0x3a; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(10)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let store = LogStore::new();
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(8, 8_192, 8_192, 64)?)?;
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));

    let first_identity = StoreBlockIdentity::new([0x6a; 16])?;
    let (first, first_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &clock,
        tenant,
        shard,
        first_identity,
        vec![record("match", "value")?],
        &schema,
    )?;
    let first_block = first.into_store_block();
    let first_digest = first_block.content_digest()?;
    let first_receipt = ledger.append(first_block)?;
    store.apply_schema_delta(&mut schema, first_delta, first_identity, first_digest)?;
    let second_identity = StoreBlockIdentity::new([0x6b; 16])?;
    let (second, second_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &clock,
        tenant,
        shard,
        second_identity,
        vec![record("match", "value")?],
        &schema,
    )?;
    let second_block = second.into_store_block();
    let second_digest = second_block.content_digest()?;
    ledger.append(second_block)?;
    store.apply_schema_delta(&mut schema, second_delta, second_identity, second_digest)?;
    let snapshot = ledger.snapshot()?;

    let through_first = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::through(ScanLimit::new(2)?, first_receipt.position()),
        &schema,
        &query("match", "value")?,
    )?;
    assert_eq!(through_first.records().len(), 1);
    assert!(through_first.complete());
    drop(through_first);

    let bounded = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &query("match", "value")?,
    )?;
    assert_eq!(bounded.records().len(), 1);
    assert!(!bounded.complete());
    drop(bounded);

    let observed = observed_schema_scan(
        &store,
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(1)?),
        &schema,
        &query("match", "value")?,
    )?;
    assert_eq!(observed.records().len(), 1);
    assert!(!observed.complete());
    drop(observed);

    let foreign = TenantId::from_bytes([0x42; 16])?;
    let failure = store
        .scan_schema(
            authority.governor(),
            foreign,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &schema,
            &query("match", "value")?,
        )
        .expect_err("cross-tenant scan must fail before query work");
    assert_eq!(failure.code(), LogStoreFailureCode::PhysicalScopeMismatch);

    let foreign_schema = SchemaCatalog::new(foreign, SchemaBudget::release_1()?)?;
    let failure = store
        .scan_schema(
            authority.governor(),
            tenant,
            &snapshot,
            LogScan::all(ScanLimit::new(1)?),
            &foreign_schema,
            &query("match", "value")?,
        )
        .expect_err("cross-tenant schema must fail before query work");
    assert_eq!(failure.code(), LogStoreFailureCode::PhysicalScopeMismatch);
    Ok(())
}

fn record(key: &str, value: &str) -> Result<LogRecord, Box<dyn Error>> {
    record_with_occurrences(key, &[value])
}

fn record_with_occurrences(key: &str, values: &[&str]) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            key.to_owned(),
            values
                .iter()
                .map(|value| CandidateAttributeValue::string((*value).to_owned()))
                .collect(),
        )],
        PolicyProvenance::new(1, [0x71; 32], vec![])?,
    )?)
}

fn signed_record(key: &str, value: i64) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            key.to_owned(),
            vec![CandidateAttributeValue::signed_integer(value)],
        )],
        PolicyProvenance::new(1, [0x72; 32], vec![])?,
    )?)
}

fn nested_record(value: &str) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            vec![CandidateAttributeValue::key_value_list(vec![
                CandidateKeyValue::new(
                    "token".to_owned(),
                    CandidateAttributeValue::string(value.to_owned()),
                ),
            ])],
        )],
        PolicyProvenance::new(1, [0x72; 32], vec![])?,
    )?)
}

fn nested_integer_record(values: Vec<Vec<CandidateKeyValue>>) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            "payload".to_owned(),
            values
                .into_iter()
                .map(CandidateAttributeValue::key_value_list)
                .collect(),
        )],
        PolicyProvenance::new(1, [0x72; 32], vec![])?,
    )?)
}

fn array_record(key: &str) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            key.to_owned(),
            vec![CandidateAttributeValue::array(vec![
                CandidateAttributeValue::boolean(true),
            ])],
        )],
        PolicyProvenance::new(1, [0x73; 32], vec![])?,
    )?)
}

fn scalar_record(key: &str, value: CandidateAttributeValue) -> Result<LogRecord, Box<dyn Error>> {
    scalar_record_in_namespace(AttributeNamespace::Record, key, value)
}

fn scalar_record_in_namespace(
    namespace: AttributeNamespace,
    key: &str,
    value: CandidateAttributeValue,
) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            namespace,
            key.to_owned(),
            vec![value],
        )],
        PolicyProvenance::new(1, [0x74; 32], vec![])?,
    )?)
}

fn query(key: &str, value: &str) -> Result<SchemaQuery, Box<dyn Error>> {
    Ok(SchemaQuery::value(
        SchemaPath::new(AttributeNamespace::Record, key.to_owned())?,
        OccurrenceSelector::Any,
        SchemaValue::string(value),
    ))
}

fn observed_schema_scan<'kernel>(
    store: &LogStore,
    governor: ResourceGovernor<'kernel>,
    tenant: TenantId,
    snapshot: &LedgerSnapshot<'_>,
    scan: LogScan,
    schema: &SchemaCatalog,
    query: &SchemaQuery,
) -> Result<LogScanResult<'kernel>, LogStoreFailure> {
    let mut observer = NoopSchemaScanObserver;
    store.scan_schema_observed(
        governor,
        tenant,
        snapshot,
        scan,
        schema,
        query,
        &NeverCancelledSchemaScan,
        &mut observer,
    )
}

struct NeverCancelledSchemaScan;

impl ScanCancellation for NeverCancelledSchemaScan {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct NoopSchemaScanObserver;

impl ScanObserver for NoopSchemaScanObserver {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        Ok(())
    }
}

impl NativeValueObserver for NoopSchemaScanObserver {
    type Error = ScanObservationFailureCode;

    fn observe_structure(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn observe_payload(&mut self, _payload: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}
