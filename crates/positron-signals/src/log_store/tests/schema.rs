use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
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
use crate::{LogStoreFailureCode, SchemaBudget, SchemaCatalog, SchemaSessionStore};

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

fn make_record(key: &str, value: &str) -> Result<LogRecord, Box<dyn Error>> {
    make_record_with_occurrences(key, &[value])
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
