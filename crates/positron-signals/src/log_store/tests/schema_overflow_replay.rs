use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    AttributeNamespace, AttributeOccurrenceSetCandidate, CandidateAttributeValue, CandidateKeyValue,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, PrimaryDataVolume, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};

use super::support::{TemporaryRoot, establish_kernel_authority, preparation_capacity};
use super::{AttributeRepresentation, LogRecord, LogScan, LogStore, ScanLimit};
use crate::log_store::schema::delta::DiscoveryMeter;
use crate::{
    OccurrenceSelector, SchemaBudget, SchemaCatalog, SchemaPath, SchemaQuery, SchemaValue,
};

#[test]
fn exhausted_overflow_traversal_never_leaves_a_nested_replay_sidecar() -> Result<(), Box<dyn Error>>
{
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1b; 16])?,
        CatalogSecret::from_owned(Box::new([0x2b; 32]), Box::new([0x3b; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(19)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x4b; 32])),
    )?;
    let store = LogStore::new();
    let identity = StoreBlockIdentity::new([0x5b; 16])?;
    let mut records = Vec::new();
    records.try_reserve_exact(6)?;
    records.push(nested_record(CandidateAttributeValue::string(
        "cataloged".to_owned(),
    ))?);
    for count in [1_024, 1_024, 1_024, 1_022] {
        records.push(filler_record(count)?);
    }
    records.push(nested_record(CandidateAttributeValue::signed_integer(42))?);

    let source = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    for record in records.iter_mut().take(5) {
        let _delta = store.stage_schema_group(std::slice::from_mut(record), &source)?;
        assert_eq!(
            record
                .attributes()
                .first()
                .map(|attribute| attribute.representation()),
            Some(AttributeRepresentation::Generic)
        );
    }
    let constrained = SchemaCatalog::new(tenant, SchemaBudget::new(1, 8_192, 512, 256)?)?;
    let overflow = records.last_mut().ok_or("overflow fixture")?;
    let _delta = store.stage_schema_group(std::slice::from_mut(overflow), &constrained)?;
    assert_eq!(
        records
            .last()
            .and_then(|record| record.attributes().first())
            .map(|attribute| attribute.representation()),
        Some(AttributeRepresentation::SchemaOverflow)
    );
    let prepared = store.prepare_unretained_for_test(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(101))),
        tenant,
        shard,
        identity,
        records,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;

    let isolated_identity = StoreBlockIdentity::new([0x6c; 16])?;
    let mut isolated_record = nested_record(CandidateAttributeValue::signed_integer(43))?;
    let _isolated_delta =
        store.stage_schema_group(std::slice::from_mut(&mut isolated_record), &constrained)?;
    assert_eq!(
        isolated_record
            .attributes()
            .first()
            .map(|attribute| attribute.representation()),
        Some(AttributeRepresentation::SchemaOverflow)
    );
    let isolated_block = store
        .prepare_unretained_for_test(
            preparation_capacity(&authority, tenant)?,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(102))),
            tenant,
            shard,
            isolated_identity,
            vec![isolated_record],
        )?
        .into_store_block();
    let _isolated_digest = isolated_block.content_digest()?;
    ledger.append(isolated_block)?;

    let seed = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "target".to_owned(),
        vec![CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new(
                "nested".to_owned(),
                CandidateAttributeValue::string("seed".to_owned()),
            ),
        ])],
    )
    .validate(LogStore::value_limit_profile())?;
    let path = SchemaPath::new(AttributeNamespace::Record, "target.nested".to_owned())?;
    let mut replayed = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    replayed.observe(std::slice::from_ref(&seed))?;
    replayed.observe(std::slice::from_ref(&seed))?;
    let filler = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "filler".to_owned(),
        vec![CandidateAttributeValue::string("fill".to_owned())],
    )
    .validate(LogStore::value_limit_profile())?;
    replayed.observe(std::slice::from_ref(&filler))?;
    replayed.observe(std::slice::from_ref(&filler))?;
    replayed.record_query_use(&path)?;
    let memory_before = replayed.memory_bytes();
    let persistent_before = replayed.persistent_bytes();
    let index_before = replayed.index_bytes();
    let snapshot = ledger.snapshot()?;
    let committed = snapshot.blocks().first().ok_or("committed block")?;
    let mut replay_delta = store.replay_schema_block(tenant, &snapshot, committed, &replayed)?;
    let cloned_replay_delta = replay_delta.try_clone()?;
    assert_eq!(
        cloned_replay_delta.staged_memory_bytes(),
        replay_delta.staged_memory_bytes()
    );
    let isolated = snapshot.blocks().get(1).ok_or("isolated committed block")?;
    let isolated_delta = store.replay_schema_block(tenant, &snapshot, isolated, &replayed)?;
    let cloned_isolated_delta = isolated_delta.try_clone()?;
    assert_eq!(
        cloned_isolated_delta.staged_memory_bytes(),
        isolated_delta.staged_memory_bytes()
    );
    let no_query_evidence = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let generic_result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(6)?),
        &no_query_evidence,
        &SchemaQuery::value(
            path.clone(),
            OccurrenceSelector::Any,
            SchemaValue::signed_integer(42),
        ),
    )?;
    assert_eq!(generic_result.records().len(), 1);
    assert!(generic_result.reduced_pruning());

    replayed.stage_record(
        std::slice::from_ref(&seed),
        &mut replay_delta,
        &mut DiscoveryMeter::new(),
    )?;
    let (replay_delta, block_index) = replay_delta.into_block_index(identity, digest);
    assert!(block_index.is_none());
    replayed.apply_delta(replay_delta, block_index)?;
    assert_eq!(replayed.memory_bytes(), memory_before);
    assert_eq!(replayed.persistent_bytes(), persistent_before);
    assert_eq!(replayed.index_bytes(), index_before);
    assert!(!replayed.has_verified_block(identity, digest));

    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(6)?),
        &replayed,
        &SchemaQuery::value(
            path,
            OccurrenceSelector::Any,
            SchemaValue::signed_integer(42),
        ),
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(result.reduced_pruning());
    Ok(())
}

fn nested_record(value: CandidateAttributeValue) -> Result<LogRecord, Box<dyn Error>> {
    record(
        vec![CandidateAttributeValue::key_value_list(vec![
            CandidateKeyValue::new("nested".to_owned(), value),
        ])],
        "target",
    )
}

fn filler_record(count: usize) -> Result<LogRecord, Box<dyn Error>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count)?;
    for _ in 0..count {
        values.push(CandidateAttributeValue::string("fill".to_owned()));
    }
    record(values, "filler")
}

fn record(values: Vec<CandidateAttributeValue>, key: &str) -> Result<LogRecord, Box<dyn Error>> {
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            key.to_owned(),
            values,
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        LogStore::value_limit_profile(),
        *evaluated,
    )?)
}
