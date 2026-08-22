use std::cell::Cell;
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
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};

use super::{AttributeRepresentation, LogRecord, LogScan, LogStore, ScanLimit};
use crate::log_store::tests::support::{
    TemporaryRoot, establish_kernel_authority, preparation_capacity,
};
use crate::{
    LogStoreFailureCode, OccurrenceSelector, ScanObservationFailureCode, ScanObserver,
    SchemaBudget, SchemaCatalog, SchemaPath, SchemaQuery, SchemaSessionStore, SchemaValue,
};

#[test]
fn schema_overflow_survives_preparation_and_kernel_scan_losslessly() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(8)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let first = make_record_with_occurrences("first", &["one", "one"])?;
    let second = make_record("second", "two")?;
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(1, 8_192, 512, 256)?)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )?;
    let store = LogStore::new();
    let identity = StoreBlockIdentity::new([0x68; 16])?;
    let (prepared, delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        vec![first.clone(), second.clone()],
        &schema,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;
    let snapshot = ledger.snapshot()?;
    let result = LogStore::new().scan(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
    )?;
    assert_eq!(result.records()[0].record(), &first);
    assert_eq!(result.records()[1].record(), &second);
    assert_eq!(
        result.records()[0].attributes()[0].representation(),
        AttributeRepresentation::Generic
    );
    assert_eq!(
        result.records()[1].attributes()[0].representation(),
        AttributeRepresentation::SchemaOverflow
    );
    assert_eq!(schema.overflow_record_count(), 1);

    let block = snapshot.blocks().first().ok_or("committed block")?;
    let replay_budget = SchemaBudget::new(1, 8_192, 512, 256)?;
    let permit_capacity = preparation_capacity(&authority, tenant)?;
    let mut replayed = SchemaSessionStore::new(permit_capacity, tenant, replay_budget)?;
    let replay_delta = replayed.replay(tenant, &snapshot, block)?;
    replayed.commit(replay_delta, block.identity(), block.content_digest()?)?;
    assert_eq!(replayed.catalog(), &schema);

    let constrained = SchemaCatalog::new(tenant, SchemaBudget::new(1, 8_192, 512, 2)?)?;
    let replay_failure = match store.replay_schema_block(tenant, &snapshot, block, &constrained) {
        Ok(_) => return Err("generic tag unexpectedly replayed as overflow".into()),
        Err(failure) => failure,
    };
    assert_eq!(replay_failure.code(), LogStoreFailureCode::InvalidInput);
    Ok(())
}

#[test]
fn discovery_work_overflow_is_cumulative_across_the_whole_group() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let mut records = (0..=4_096)
        .map(|_| make_record("bounded", "value"))
        .collect::<Result<Vec<_>, _>>()?;

    let delta = LogStore::new().stage_schema_group(&mut records, &schema)?;
    assert_eq!(
        records
            .first()
            .and_then(|record| record.attributes().first())
            .map(|attribute| attribute.representation()),
        Some(AttributeRepresentation::Generic)
    );
    assert_eq!(
        records
            .last()
            .and_then(|record| record.attributes().first())
            .map(|attribute| attribute.representation()),
        Some(AttributeRepresentation::SchemaOverflow)
    );
    let mut applied = schema;
    LogStore::new().apply_schema_delta(
        &mut applied,
        delta,
        StoreBlockIdentity::new([0x91; 16])?,
        [0x92; 32],
    )?;
    assert_eq!(applied.overflow_record_count(), 1);
    Ok(())
}

#[test]
fn observed_text_staging_has_an_exact_work_boundary_and_is_atomic() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x42; 16])?;
    let schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let mut records = vec![make_text_record("prefix needle suffix")?];
    let unlimited = ObservationMeter::bounded(u64::MAX);
    let delta = LogStore::new().stage_schema_group_observed(&mut records, &schema, &unlimited)?;
    let consumed = unlimited.consumed.get();
    assert!(consumed > 0);
    assert!(delta.physical_memory_bytes() > 0);

    let mut records = vec![make_text_record("prefix needle suffix")?];
    let exact_minus_one = ObservationMeter::bounded(consumed - 1);
    let fallback = match LogStore::new().stage_schema_group_observed(
        &mut records,
        &schema,
        &exact_minus_one,
    ) {
        Ok(delta) => delta,
        Err(_) => return Err("unexpected staging failure".into()),
    };
    assert_eq!(fallback.physical_memory_bytes(), 0);
    let empty = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    assert_eq!(schema.memory_bytes(), empty.memory_bytes());
    Ok(())
}

#[test]
fn observed_text_staging_polls_cancellation_before_publication() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x43; 16])?;
    let schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let before = schema.memory_bytes();
    let mut records = vec![make_text_record(&"x".repeat(2_048))?];
    let cancelling = ObservationMeter::cancelling(0);
    let failure =
        match LogStore::new().stage_schema_group_observed(&mut records, &schema, &cancelling) {
            Ok(_) => return Err("cancellation unexpectedly succeeded".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);
    assert_eq!(schema.memory_bytes(), before);
    Ok(())
}

#[test]
fn observed_text_staging_maps_attach_cancellation_without_publication() -> Result<(), Box<dyn Error>>
{
    let tenant = TenantId::from_bytes([0x44; 16])?;
    let schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let mut records = vec![make_text_record("abc")?];
    let observer = CancelOnCall::new(3);
    let failure =
        match LogStore::new().stage_schema_group_observed(&mut records, &schema, &observer) {
            Ok(_) => return Err("attach cancellation unexpectedly succeeded".into()),
            Err(failure) => failure,
        };
    assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);
    assert_eq!(
        schema.memory_bytes(),
        SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?.memory_bytes()
    );
    Ok(())
}

#[test]
fn observed_text_replay_has_an_exact_work_boundary_and_falls_back_atomically()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x54; 16])?,
        CatalogSecret::from_owned(Box::new([0x64; 32]), Box::new([0x74; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(24)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x84; 32])),
    )?;
    let store = LogStore::new();
    let identity = StoreBlockIdentity::new([0x94; 16])?;
    let block = store
        .prepare(
            preparation_capacity(&authority, tenant)?,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(120))),
            tenant,
            shard,
            identity,
            vec![make_text_record("abc")?],
        )?
        .into_store_block();
    ledger.append(block)?;
    let snapshot = ledger.snapshot()?;
    let block = snapshot.blocks().first().ok_or("committed block")?;
    let schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let unlimited = ObservationMeter::bounded(u64::MAX);
    let delta =
        store.replay_schema_block_observed(tenant, &snapshot, block, &schema, &unlimited)?;
    let consumed = unlimited.consumed.get();
    assert!(consumed > 0);
    assert!(delta.physical_memory_bytes() > 0);

    let exact_minus_one = ObservationMeter::bounded(consumed - 1);
    let fallback =
        store.replay_schema_block_observed(tenant, &snapshot, block, &schema, &exact_minus_one)?;
    assert_eq!(fallback.physical_memory_bytes(), 0);

    let unobserved = store.replay_schema_block(tenant, &snapshot, block, &schema)?;
    assert!(unobserved.physical_memory_bytes() > 0);
    let foreign = SchemaCatalog::new(
        TenantId::from_bytes([0x45; 16])?,
        SchemaBudget::release_1()?,
    )?;
    let foreign_result = store.replay_schema_block(tenant, &snapshot, block, &foreign);
    let foreign_failure = match foreign_result {
        Ok(_) => return Err("replay accepted a foreign schema tenant".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        foreign_failure.code(),
        LogStoreFailureCode::PhysicalScopeMismatch
    );

    let cancelled_during_summary = CancelOnCall::new(1);
    let failure = match store.replay_schema_block_observed(
        tenant,
        &snapshot,
        block,
        &schema,
        &cancelled_during_summary,
    ) {
        Ok(_) => return Err("summary cancellation unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);

    let cancelled_during_attach = CancelOnCall::new(3);
    let failure = match store.replay_schema_block_observed(
        tenant,
        &snapshot,
        block,
        &schema,
        &cancelled_during_attach,
    ) {
        Ok(_) => return Err("attach cancellation unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), LogStoreFailureCode::Cancelled);
    Ok(())
}

struct ObservationMeter {
    consumed: Cell<u64>,
    limit: u64,
    cancel_after: Option<u64>,
}

impl ObservationMeter {
    const fn bounded(limit: u64) -> Self {
        Self {
            consumed: Cell::new(0),
            limit,
            cancel_after: None,
        }
    }

    const fn cancelling(after: u64) -> Self {
        Self {
            consumed: Cell::new(0),
            limit: u64::MAX,
            cancel_after: Some(after),
        }
    }
}

impl ScanObserver for ObservationMeter {
    fn observe_work(&self, units: u64) -> Result<(), ScanObservationFailureCode> {
        let consumed = self.consumed.get().saturating_add(units);
        self.consumed.set(consumed);
        if self.cancel_after.is_some_and(|after| consumed > after) {
            return Err(ScanObservationFailureCode::Cancelled);
        }
        if consumed > self.limit {
            Err(ScanObservationFailureCode::BudgetExhausted)
        } else {
            Ok(())
        }
    }
}

struct CancelOnCall {
    calls: Cell<u64>,
    fail_at: u64,
}

impl CancelOnCall {
    const fn new(fail_at: u64) -> Self {
        Self {
            calls: Cell::new(0),
            fail_at,
        }
    }
}

impl ScanObserver for CancelOnCall {
    fn observe_work(&self, _units: u64) -> Result<(), ScanObservationFailureCode> {
        let calls = self.calls.get().saturating_add(1);
        self.calls.set(calls);
        if calls == self.fail_at {
            Err(ScanObservationFailureCode::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[test]
fn staged_schema_delta_cannot_be_applied_to_another_tenant() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_bytes([0x81; 16])?;
    let foreign = TenantId::from_bytes([0x82; 16])?;
    let schema = SchemaCatalog::new(tenant, SchemaBudget::release_1()?)?;
    let mut records = vec![make_record("tenant", "bound")?];
    let delta = LogStore::new().stage_schema_group(&mut records, &schema)?;
    let mut foreign_schema = SchemaCatalog::new(foreign, SchemaBudget::release_1()?)?;
    let failure = LogStore::new()
        .apply_schema_delta(
            &mut foreign_schema,
            delta,
            StoreBlockIdentity::new([0x93; 16])?,
            [0x94; 32],
        )
        .expect_err("delta must retain its staging tenant");
    assert_eq!(
        failure.code(),
        super::super::LogStoreFailureCode::PhysicalScopeMismatch
    );
    Ok(())
}

#[test]
fn same_block_overflow_keeps_integer_query_unpruned() -> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x1a; 16])?,
        CatalogSecret::from_owned(Box::new([0x2a; 32]), Box::new([0x3a; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(18)?;
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x5a; 32])),
    )?;
    let mut schema = SchemaCatalog::new(tenant, SchemaBudget::new(1, 8_192, 8_192, 97)?)?;
    let seed = AttributeOccurrenceSetCandidate::new(
        AttributeNamespace::Record,
        "collision".to_owned(),
        vec![CandidateAttributeValue::string("seed".to_owned())],
    )
    .validate(LogStore::value_limit_profile())?;
    schema.observe(std::slice::from_ref(&seed))?;
    schema.observe(std::slice::from_ref(&seed))?;
    let path = SchemaPath::new(AttributeNamespace::Record, "collision".to_owned())?;
    schema.record_query_use(&path)?;
    assert!(
        schema
            .entry(&path)
            .ok_or("promoted path missing")?
            .promoted()
    );

    schema.remove_query_evidence(&path)?;
    let store = LogStore::new();
    let seed_identity = StoreBlockIdentity::new([0x5a; 16])?;
    let (prepared, seed_delta) = store.prepare_with_schema_delta(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(90))),
        tenant,
        shard,
        seed_identity,
        vec![
            make_record("collision", "seed-one")?,
            make_record("collision", "seed-two")?,
        ],
        &schema,
    )?;
    let seed_block = prepared.into_store_block();
    let seed_digest = seed_block.content_digest()?;
    ledger.append(seed_block)?;
    store.apply_schema_delta(&mut schema, seed_delta, seed_identity, seed_digest)?;
    schema.record_query_use(&path)?;

    let identity = StoreBlockIdentity::new([0x6a; 16])?;
    let mut records = vec![
        make_record("collision", "cataloged")?,
        make_integer_record("collision", 42)?,
        make_record("collision", "still-cataloged")?,
    ];
    let delta = store.stage_schema_group(&mut records, &schema)?;
    assert_eq!(
        records[0].attributes()[0].representation(),
        AttributeRepresentation::Generic
    );
    assert_eq!(
        records[1].attributes()[0].representation(),
        AttributeRepresentation::SchemaOverflow
    );
    assert_eq!(
        records[2].attributes()[0].representation(),
        AttributeRepresentation::Generic
    );
    let prepared = store.prepare(
        preparation_capacity(&authority, tenant)?,
        &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
        tenant,
        shard,
        identity,
        records,
    )?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger.append(block)?;
    store.apply_schema_delta(&mut schema, delta, identity, digest)?;

    let result = store.scan_schema(
        authority.governor(),
        tenant,
        &ledger.snapshot()?,
        LogScan::all(ScanLimit::new(3)?),
        &schema,
        &SchemaQuery::value(
            path.clone(),
            OccurrenceSelector::Any,
            SchemaValue::signed_integer(42),
        ),
    )?;
    assert_eq!(result.records().len(), 1);
    assert!(result.reduced_pruning());

    let snapshot = ledger.snapshot()?;
    let replay_capacity = preparation_capacity(&authority, tenant)?;
    let mut replayed = SchemaSessionStore::new(
        replay_capacity,
        tenant,
        SchemaBudget::new(1, 8_192, 8_192, 97)?,
    )?;
    let seed = snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == seed_identity)
        .ok_or("replay seed block")?;
    let seed_delta = replayed.replay(tenant, &snapshot, seed)?;
    replayed.commit(seed_delta, seed.identity(), seed.content_digest()?)?;
    let mut query_update = replayed.stage_query_update()?;
    query_update.record_query_use(&path)?;
    replayed.commit_query_update(query_update)?;
    let target = snapshot
        .blocks()
        .iter()
        .find(|block| block.identity() == identity)
        .ok_or("replay target block")?;
    let target_delta = replayed.replay(tenant, &snapshot, target)?;
    replayed.commit(target_delta, target.identity(), target.content_digest()?)?;
    let mut query_update = replayed.stage_query_update()?;
    query_update.index_replayed_query_path(tenant, &snapshot, target, &path)?;
    replayed.commit_query_update(query_update)?;
    let replayed_result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(5)?),
        replayed.catalog(),
        &SchemaQuery::value(
            path,
            OccurrenceSelector::Any,
            SchemaValue::signed_integer(42),
        ),
    )?;
    assert_eq!(replayed_result.records().len(), 1);
    assert_eq!(replayed_result.records(), result.records());
    assert!(replayed_result.reduced_pruning());
    assert_eq!(replayed_result.reduced_pruning(), result.reduced_pruning());
    Ok(())
}

fn make_record(key: &str, value: &str) -> Result<LogRecord, Box<dyn Error>> {
    make_record_with_occurrences(key, &[value])
}

fn make_text_record(body: &str) -> Result<LogRecord, Box<dyn Error>> {
    let policy = IngestPolicy::preserving(1)?;
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string(body.to_owned())),
        Vec::new(),
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        LogStore::value_limit_profile(),
        *evaluated,
    )?)
}

fn make_record_with_occurrences(key: &str, values: &[&str]) -> Result<LogRecord, Box<dyn Error>> {
    let policy = IngestPolicy::preserving(1)?;
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            key.to_owned(),
            values
                .iter()
                .map(|value| CandidateAttributeValue::string((*value).to_owned()))
                .collect(),
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        LogStore::value_limit_profile(),
        *evaluated,
    )?)
}

fn make_integer_record(key: &str, value: i64) -> Result<LogRecord, Box<dyn Error>> {
    let policy = IngestPolicy::preserving(1)?;
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            key.to_owned(),
            vec![CandidateAttributeValue::signed_integer(value)],
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        policy.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected fixture".into());
    };
    Ok(LogRecord::checked_evaluated(
        LogStore::value_limit_profile(),
        *evaluated,
    )?)
}
