use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue,
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
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(1, 512, 512, 8)?)?;
    let records = vec![record("indexed", "one")?, record("overflow", "two")?];
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        StoreBlockIdentity::new([0x69; 16])?,
        records,
        &schema,
    )?;
    ledger.append(prepared.into_store_block())?;
    store.apply_schema_delta(&mut schema, delta)?;
    let checkpoint = schema.encode_catalog_object()?;
    let mut reopened = SchemaCatalog::decode_catalog_object(&checkpoint)?;
    let snapshot = ledger.snapshot()?;

    let indexed = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &mut schema,
        &query("indexed", "one")?,
    )?;
    assert_eq!(indexed.records().len(), 1);
    assert!(!indexed.reduced_pruning());
    let indexed_reopened = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &mut reopened,
        &query("indexed", "one")?,
    )?;
    assert_eq!(indexed_reopened.records(), indexed.records());
    assert_eq!(
        indexed_reopened.reduced_pruning(),
        indexed.reduced_pruning()
    );

    let overflow = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &mut schema,
        &query("overflow", "two")?,
    )?;
    assert_eq!(overflow.records().len(), 1);
    assert!(overflow.reduced_pruning());
    let overflow_reopened = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        &mut reopened,
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

    let (first, first_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &clock,
        tenant,
        shard,
        StoreBlockIdentity::new([0x6a; 16])?,
        vec![record("match", "value")?],
        &schema,
    )?;
    let first_receipt = ledger.append(first.into_store_block())?;
    store.apply_schema_delta(&mut schema, first_delta)?;
    let (second, second_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &clock,
        tenant,
        shard,
        StoreBlockIdentity::new([0x6b; 16])?,
        vec![record("match", "value")?],
        &schema,
    )?;
    ledger.append(second.into_store_block())?;
    store.apply_schema_delta(&mut schema, second_delta)?;
    let snapshot = ledger.snapshot()?;

    let through_first = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::through(ScanLimit::new(2)?, first_receipt.position()),
        &mut schema,
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
        &mut schema,
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
            &mut schema,
            &query("match", "value")?,
        )
        .expect_err("cross-tenant scan must fail before query work");
    assert_eq!(failure.code(), LogStoreFailureCode::PhysicalScopeMismatch);
    Ok(())
}

fn record(key: &str, value: &str) -> Result<LogRecord, Box<dyn Error>> {
    Ok(LogRecord::checked_receiver_candidate(
        LogStore::value_limit_profile(),
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![AttributeOccurrenceSetCandidate::new(
            AttributeNamespace::Record,
            key.to_owned(),
            vec![CandidateAttributeValue::string(value.to_owned())],
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
