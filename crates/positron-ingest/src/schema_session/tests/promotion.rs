use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::AttributeNamespace;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, ResourceAmounts, ResourceDimension, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_policy::{IngestPolicy, PolicyEvaluation};
use positron_signals::{
    LogRecord, LogScan, LogStore, OccurrenceSelector, ScanLimit, SchemaCatalog,
    SchemaDiscoveryRequest, SchemaPath, SchemaQuery, SchemaValue,
};

use super::super::{DurableSchemaOutcome, TenantSchemaRegistry};

#[test]
fn governed_query_evidence_promotes_demotes_and_reopens_equivalently() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xa1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(211).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0xa4; 32])),
    )
    .expect("ledger");
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let identity = StoreBlockIdentity::new([0xa5; 16]).expect("identity");
    let path = SchemaPath::root(AttributeNamespace::Record, "order.id".to_owned()).expect("path");
    let mut records = records();
    let empty_snapshot = ledger.snapshot().expect("empty");
    let delta = session
        .stage_group(
            fixture.tenant,
            shard,
            identity,
            &empty_snapshot,
            &mut records,
            fixture.authority.governor(),
        )
        .expect("stage");
    assert_eq!(
        session.record_query_use(
            fixture.tenant,
            &path,
            &empty_snapshot,
            fixture.authority.governor(),
        ),
        Err(super::super::SchemaSessionFailure::InFlight)
    );
    let prepared = LogStore::new()
        .prepare(
            preparation_capacity(&fixture),
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1))),
            fixture.tenant,
            shard,
            identity,
            records,
        )
        .expect("prepare")
        .into_store_block();
    let digest = prepared.content_digest().expect("digest");
    let receipt = ledger.append(prepared).expect("append");
    session
        .resolve_durable_outcome(
            identity,
            shard,
            delta,
            None,
            0,
            DurableSchemaOutcome::Committed {
                position: receipt.position(),
                digest,
            },
        )
        .expect("commit schema");

    let query = SchemaQuery::value(
        SchemaPath::root(AttributeNamespace::Record, "order.id".to_owned()).expect("path"),
        OccurrenceSelector::Any,
        SchemaValue::string("A-1"),
    );
    let snapshot = ledger.snapshot().expect("snapshot");
    let initial = decoded(&session);
    assert!(!initial.entry(&path).expect("entry").promoted());
    assert!(scan(&fixture, &snapshot, &initial, &query).reduced_pruning());

    session
        .record_query_use(
            fixture.tenant,
            &path,
            &snapshot,
            fixture.authority.governor(),
        )
        .expect("promote");
    let promoted = decoded(&session);
    let promoted_result = scan(&fixture, &snapshot, &promoted, &query);
    assert!(promoted.entry(&path).expect("entry").promoted());
    assert!(!promoted_result.reduced_pruning());
    let mut reachable = Vec::new();
    session
        .append_reachable_indexes(&snapshot, &mut reachable)
        .expect("reachable sidecar");
    session
        .append_reachable_indexes(&snapshot, &mut reachable)
        .expect("deduplicated reachable sidecar");
    assert_eq!(reachable.len(), 1);
    let mut full = (1_u128..=4_096)
        .map(|sequence| {
            (
                StoreBlockIdentity::new(sequence.to_be_bytes()).expect("identity"),
                [0x01; 32],
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        session.append_reachable_indexes(&snapshot, &mut full),
        Err(super::super::SchemaSessionFailure::ReplayLimitExceeded)
    );
    let foreign = TenantId::from_bytes([0xaf; 16]).expect("foreign tenant");
    assert_eq!(
        session.discover(foreign, SchemaDiscoveryRequest::new(1, 0).expect("request")),
        Err(super::super::SchemaSessionFailure::TenantConflict)
    );
    assert_eq!(
        session.record_query_use(foreign, &path, &snapshot, fixture.authority.governor()),
        Err(super::super::SchemaSessionFailure::TenantConflict)
    );
    assert_eq!(
        session.remove_query_evidence(foreign, &path),
        Err(super::super::SchemaSessionFailure::TenantConflict)
    );
    session
        .retain_reachable_indexes(&[])
        .expect("reconcile unreachable sidecar");
    let reconciled = decoded(&session);
    let reconciled_result = scan(&fixture, &snapshot, &reconciled, &query);
    assert!(reconciled_result.reduced_pruning());
    assert_eq!(reconciled_result.records(), promoted_result.records());

    session
        .remove_query_evidence(fixture.tenant, &path)
        .expect("demote");
    let demoted = decoded(&session);
    let demoted_result = scan(&fixture, &snapshot, &demoted, &query);
    assert!(!demoted.entry(&path).expect("entry").promoted());
    assert!(demoted_result.reduced_pruning());
    assert_eq!(demoted_result.records(), promoted_result.records());
    let reopened = SchemaCatalog::decode_catalog_object(
        session.checkpoint().expect("checkpoint").catalog_bytes(),
    )
    .expect("reopen");
    assert_eq!(
        scan(&fixture, &snapshot, &reopened, &query).records(),
        promoted_result.records()
    );
}

fn decoded(session: &super::super::TenantSchemaSession) -> SchemaCatalog {
    SchemaCatalog::decode_catalog_object(session.checkpoint().expect("checkpoint").catalog_bytes())
        .expect("decode")
}

fn scan<'a>(
    fixture: &'a crate::tests::support::Fixture,
    snapshot: &positron_kernel::LedgerSnapshot<'_>,
    catalog: &SchemaCatalog,
    query: &SchemaQuery,
) -> positron_signals::LogScanResult<'a> {
    LogStore::new()
        .scan_schema(
            fixture.authority.governor(),
            fixture.tenant,
            snapshot,
            LogScan::all(ScanLimit::new(4).expect("limit")),
            catalog,
            query,
        )
        .expect("scan")
}

fn records() -> Vec<LogRecord> {
    let batch = crate::OtlpLogsReceiver::new()
        .decode(crate::tests::support::protobuf_request())
        .expect("batch");
    let (_, candidates, profile, _, receiver) = batch.into_parts();
    let policy = IngestPolicy::preserving(1).expect("policy");
    candidates
        .into_iter()
        .filter_map(
            |candidate| match policy.evaluate(candidate, receiver).expect("policy") {
                PolicyEvaluation::Accepted(record) => {
                    Some(LogRecord::checked_evaluated(profile, *record).expect("record"))
                },
                PolicyEvaluation::Rejected => None,
            },
        )
        .collect()
}

fn preparation_capacity(
    fixture: &crate::tests::support::Fixture,
) -> positron_kernel::ResourceReservation<'_> {
    fixture
        .authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                fixture.tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 1_048_576).expect("amounts"),
            )
            .expect("claim"),
        )
        .expect("capacity")
}
