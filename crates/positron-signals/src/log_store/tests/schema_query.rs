use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, AttributeValueKind,
    CandidateAttributeValue,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};

use super::{LogRecord, LogScan, LogStore, PolicyProvenance, ScanLimit};
use crate::log_store::tests::support::{
    TemporaryRoot, establish_kernel_authority, preparation_capacity,
};
use crate::{
    LogStoreFailureCode, OccurrenceSelector, SchemaBudget, SchemaCatalog, SchemaPath, SchemaQuery,
    SchemaValue,
};

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
    schema.observe(&[seed])?;
    schema.record_query_use(&SchemaPath::root(
        AttributeNamespace::Record,
        "indexed".to_owned(),
    )?)?;
    let records = vec![
        record_with_occurrences("indexed", &["one", "one"])?,
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
    let checkpoint = schema.encode_catalog_object()?;
    let reopened = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    let snapshot = ledger.snapshot()?;

    let indexed = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &query("indexed", "one")?,
    )?;
    assert_eq!(indexed.records().len(), 1);
    assert!(!indexed.reduced_pruning());
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
    let stale = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &stale_digest,
        &query("indexed", "one")?,
    )?;
    assert_eq!(stale.records(), indexed.records());
    assert!(stale.reduced_pruning());

    let mut replacement_identity = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    replacement_identity.block_indexes[0].identity = StoreBlockIdentity::new([0x7a; 16])?;
    let replacement = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &replacement_identity,
        &query("indexed", "one")?,
    )?;
    assert_eq!(replacement.records(), indexed.records());
    assert!(replacement.reduced_pruning());

    let mut forged_kinds = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    forged_kinds.block_indexes[0].paths[0].kind_mask = 1 << 1;
    let forged = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &forged_kinds,
        &query("indexed", "one")?,
    )?;
    assert_eq!(forged.records(), indexed.records());
    assert!(forged.reduced_pruning());

    let generic = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let demoted = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
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
        SchemaValue::kind(AttributeValueKind::Array),
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

    let overflow = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &schema,
        &query("overflow", "two")?,
    )?;
    assert_eq!(overflow.records().len(), 1);
    assert!(overflow.reduced_pruning());
    let overflow_reopened = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &reopened,
        &query("overflow", "two")?,
    )?;
    assert_eq!(overflow_reopened.records(), overflow.records());
    assert_eq!(
        overflow_reopened.reduced_pruning(),
        overflow.reduced_pruning()
    );
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

fn query(key: &str, value: &str) -> Result<SchemaQuery, Box<dyn Error>> {
    Ok(SchemaQuery::value(
        SchemaPath::new(AttributeNamespace::Record, key.to_owned())?,
        OccurrenceSelector::Any,
        SchemaValue::string(value),
    ))
}
