use std::error::Error;

use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue, ValueLimitProfile};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, MountQualification, ResourceAmounts, ResourceDimension, SegmentProtectionKey,
    SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::{
    LogRecord, LogScan, LogStore, OccurrenceSelector, ScanLimit, SchemaBudget, SchemaPath,
    SchemaQuery, SchemaSessionStore, SchemaValue,
};

#[path = "../src/log_store/tests/support.rs"]
mod support;

use support::{TemporaryRoot, establish_kernel_authority, preparation_capacity};

#[test]
fn public_scalar_query_checkpoint_and_missing_or_stale_fallbacks_preserve_results()
-> Result<(), Box<dyn Error>> {
    let root = TemporaryRoot::new()?;
    let volume = MountQualification::LocalHost;
    let volume = positron_kernel::PrimaryDataVolume::acquire(root.path(), volume)?;
    let authority = establish_kernel_authority(volume)?;
    let catalog = Catalog::open(
        &authority,
        InstanceId::new([0x18; 16])?,
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )?;
    let tenant = TenantId::from_bytes([0x41; 16])?;
    let shard = VirtualShardId::new(8)?;
    let scope = SegmentScope::new(tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )
    .map_err(|failure| format!("open ledger: {failure:?}"))?;
    let store = LogStore::new();
    let budget = SchemaBudget::new(8, 200_000, 1_000_000, 100_000)?;
    let reserve_schema = || -> Result<_, Box<dyn Error>> {
        Ok(authority.governor().reserve(WorkClaim::tenant(
            tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 200_000)?,
        )?)?)
    };
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("public scalar".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "indexed".to_owned(),
            vec![
                CandidateAttributeValue::string("one".to_owned()),
                CandidateAttributeValue::string("two".to_owned()),
                CandidateAttributeValue::string("one".to_owned()),
            ],
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) =
        IngestPolicy::preserving(1)?.evaluate(candidate, PolicyReceiver::OtlpGrpc)?
    else {
        return Err("preserving policy rejected the public fixture".into());
    };
    let record =
        LogRecord::checked_evaluated(ValueLimitProfile::release_1_system_maximum(), *evaluated)?;
    let path = SchemaPath::root(AttributeNamespace::Record, "indexed".to_owned())?;
    let query = SchemaQuery::value(
        path.clone(),
        OccurrenceSelector::Any,
        SchemaValue::string("one"),
    );

    let mut session = SchemaSessionStore::new(reserve_schema()?, tenant, budget)?;
    let mut seed = vec![record.clone()];
    let seed_delta = session.stage_group(&mut seed)?;
    session.commit(seed_delta, StoreBlockIdentity::new([0x86; 16])?, [0x87; 32])?;
    let mut query_update = session.stage_query_update()?;
    query_update.record_query_use(&path)?;
    session.commit_query_update(query_update)?;

    let identity = StoreBlockIdentity::new([0x88; 16])?;
    let mut durable = vec![record];
    let delta = session.stage_group(&mut durable)?;
    let prepared = store
        .prepare(
            preparation_capacity(&authority, tenant)?,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(800))),
            tenant,
            shard,
            identity,
            durable,
        )
        .map_err(|failure| format!("prepare durable block: {failure:?}"))?;
    let block = prepared.into_store_block();
    let digest = block.content_digest()?;
    ledger
        .append(block)
        .map_err(|failure| format!("append durable block: {failure:?}"))?;
    session.commit(delta, identity, digest)?;

    let checkpoint = session.catalog().encode_checkpoint_object(&[])?;
    let (reopened, _) =
        SchemaSessionStore::from_checkpoint(reserve_schema()?, tenant, &checkpoint)?
            .ok_or("checkpoint tenant")?;
    let snapshot = ledger.snapshot()?;
    let indexed = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        reopened.catalog(),
        &query,
    )?;
    assert_eq!(indexed.records().len(), 1);
    assert!(!indexed.reduced_pruning());

    let (mut missing, _) =
        SchemaSessionStore::from_checkpoint(reserve_schema()?, tenant, &checkpoint)?
            .ok_or("missing fallback tenant")?;
    missing.retain_reachable_indexes(&[])?;
    let fallback = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        missing.catalog(),
        &query,
    )?;
    assert_eq!(fallback.records(), indexed.records());
    assert!(fallback.reduced_pruning());

    let (mut stale, _) =
        SchemaSessionStore::from_checkpoint(reserve_schema()?, tenant, &checkpoint)?
            .ok_or("stale fallback tenant")?;
    stale.retain_reachable_indexes(&[(identity, [0x99; 32])])?;
    let stale_result = store.scan_schema(
        authority.governor(),
        tenant,
        &snapshot,
        LogScan::all(ScanLimit::new(2)?),
        stale.catalog(),
        &query,
    )?;
    assert_eq!(stale_result.records(), indexed.records());
    assert!(stale_result.reduced_pruning());
    Ok(())
}
