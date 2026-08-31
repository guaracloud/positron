use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::value::AttributeNamespace;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity,
};
use positron_policy::{IngestPolicy, PolicyEvaluation};
use positron_signals::{LogRecord, SchemaDiscoveryRequest, SchemaPath};

use super::super::{
    DurableSchemaOutcome, DurableSchemaResolution, SchemaSessionFailure, TenantSchemaRegistry,
};

#[test]
fn staging_and_resolution_reject_mismatched_authority_without_publication() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = catalog(&fixture, 0xb1);
    let shard = VirtualShardId::new(401).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xb2);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let snapshot = ledger.snapshot().expect("snapshot");
    let foreign_tenant = TenantId::from_bytes([0xb3; 16]).expect("tenant");
    let foreign_governor =
        crate::tests::support::fixture_for_tenant(fixture.tenant).expect("foreign governor");

    let mut rejected = records();
    assert!(matches!(
        session.stage_group(
            foreign_tenant,
            shard,
            StoreBlockIdentity::new([0xb4; 16]).expect("identity"),
            &snapshot,
            &mut rejected,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::TenantConflict)
    ));
    assert!(matches!(
        session.stage_group(
            fixture.tenant,
            shard,
            StoreBlockIdentity::new([0xb5; 16]).expect("identity"),
            &snapshot,
            &mut rejected,
            foreign_governor.authority.governor(),
        ),
        Err(SchemaSessionFailure::StateUnavailable)
    ));

    let identity = StoreBlockIdentity::new([0xb6; 16]).expect("identity");
    let mut accepted = records();
    let staged = session
        .stage_group(
            fixture.tenant,
            shard,
            identity,
            &snapshot,
            &mut accepted,
            fixture.authority.governor(),
        )
        .expect("stage");
    assert!(matches!(
        session.stage_group(
            fixture.tenant,
            shard,
            StoreBlockIdentity::new([0xb7; 16]).expect("identity"),
            &snapshot,
            &mut accepted,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::InFlight)
    ));
    assert_eq!(
        session.resolve_durable_outcome(
            DurableSchemaResolution {
                identity: StoreBlockIdentity::new([0xb8; 16]).expect("identity"),
                shard,
                staged,
                capacity: None,
                capacity_bytes: 0,
                outcome: DurableSchemaOutcome::DefiniteFailure,
            },
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::InFlight)
    );
    assert_eq!(session.checkpoint().expect("checkpoint").entry_count(), 0);
}

#[test]
fn immutable_inspection_and_replay_are_tenant_and_governor_bound() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = catalog(&fixture, 0xc1);
    let shard = VirtualShardId::new(402).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xc2);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let snapshot = ledger.snapshot().expect("snapshot");
    let discovery = session
        .discover(
            fixture.tenant,
            SchemaDiscoveryRequest::new(1, 1).expect("request"),
        )
        .expect("discovery");
    assert_eq!(discovery.tenant(), fixture.tenant);
    assert_eq!(discovery.total_paths(), 0);

    let foreign =
        crate::tests::support::fixture_for_tenant(fixture.tenant).expect("foreign governor");
    let path = SchemaPath::root(AttributeNamespace::Record, "missing".to_owned()).expect("path");
    assert_eq!(
        session.record_query_use(
            fixture.tenant,
            &path,
            &snapshot,
            foreign.authority.governor(),
        ),
        Err(SchemaSessionFailure::StateUnavailable)
    );
    assert_eq!(
        session.replay_snapshot(
            TenantId::from_bytes([0xc3; 16]).expect("tenant"),
            &snapshot,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::TenantConflict)
    );
    assert_eq!(
        session.replay_snapshot(fixture.tenant, &snapshot, foreign.authority.governor()),
        Err(SchemaSessionFailure::StateUnavailable)
    );
}

#[test]
fn immutable_catalog_guard_is_released_before_returned_delivery_is_consumed() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let delivery_session = session.clone();
    let mut delivery = session
        .with_catalog_view(fixture.tenant, |_| {
            std::iter::once_with(move || delivery_session.checkpoint())
        })
        .expect("catalog view");

    let checkpoint = delivery
        .next()
        .expect("first delivery")
        .expect("catalog guard remained held during delivery");
    assert_eq!(checkpoint.entry_count(), 0);
}

fn catalog<'fixture>(
    fixture: &'fixture crate::tests::support::Fixture,
    marker: u8,
) -> Catalog<'fixture> {
    Catalog::open(
        &fixture.authority,
        InstanceId::new([marker; 16]).expect("instance"),
        CatalogSecret::from_owned(
            Box::new([marker.wrapping_add(1); 32]),
            Box::new([marker; 32]),
        ),
    )
    .expect("catalog")
}

fn ledger<'authority, 'catalog>(
    fixture: &'authority crate::tests::support::Fixture,
    catalog: &'catalog Catalog<'authority>,
    shard: VirtualShardId,
    marker: u8,
) -> ActiveSegmentLedger<'authority, 'catalog> {
    ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([marker; 32])),
    )
    .expect("ledger")
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
