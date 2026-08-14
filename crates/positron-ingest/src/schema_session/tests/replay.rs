use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_policy::IngestPolicy;
use positron_signals::{SchemaCatalog, SchemaCheckpointFrontier};

use super::super::{SchemaSessionFailure, TenantSchemaRegistry, TenantSchemaSession};
use crate::{IngestOutcome, LogIngest, OtlpLogsReceiver};

#[test]
fn rebuild_from_committed_custom_shards_is_canonical_and_idempotent() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )
    .expect("catalog");
    let first_shard = VirtualShardId::new(301).expect("shard");
    let second_shard = VirtualShardId::new(302).expect("shard");
    let first = ledger(&fixture, &catalog, first_shard, 0xd4);
    let second = ledger(&fixture, &catalog, second_shard, 0xd5);
    let live_registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = live_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("live session");
    ingest(&fixture, &first, first_shard, live.clone(), 0xd6);
    ingest(&fixture, &second, second_shard, live.clone(), 0xd7);
    let expected = live
        .checkpoint()
        .expect("live checkpoint")
        .catalog_bytes()
        .to_vec();
    assert_eq!(
        catalog
            .pin()
            .expect("catalog snapshot")
            .reachable_ledger_scopes(fixture.tenant, SignalKind::Logs)
            .expect("reachable scopes"),
        vec![
            SegmentScope::new(fixture.tenant, SignalKind::Logs, first_shard),
            SegmentScope::new(fixture.tenant, SignalKind::Logs, second_shard),
        ]
    );
    let first_snapshot = first.snapshot().expect("first snapshot");
    let second_snapshot = second.snapshot().expect("second snapshot");
    drop(live);
    drop(live_registry);

    let left = replay(&fixture, [&first_snapshot, &second_snapshot], None, true);
    let right = replay(&fixture, [&second_snapshot, &first_snapshot], None, false);
    assert_eq!(left, expected);
    assert_eq!(right, expected);
    assert_eq!(left, right);
}

#[test]
fn checkpoint_frontier_rejects_identity_or_digest_mismatch() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xe1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(303).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xe4);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    ingest(&fixture, &ledger, shard, live.clone(), 0xe5);
    let checkpoint = live.checkpoint().expect("checkpoint");
    let snapshot = ledger.snapshot().expect("snapshot");
    let (schema, frontiers) =
        SchemaCatalog::decode_checkpoint_object(checkpoint.catalog_bytes()).expect("decode");
    let known = frontiers.first().copied().expect("frontier");
    let canonical = schema
        .encode_checkpoint_object(&frontiers)
        .expect("checkpoint");
    assert!(matches!(
        TenantSchemaSession::from_checkpoint(
            TenantId::from_bytes([0xef; 16]).expect("foreign tenant"),
            &canonical,
        ),
        Err(SchemaSessionFailure::TenantConflict)
    ));
    drop(live);
    drop(registry);

    let foreign_registry = TenantSchemaRegistry::new(1).expect("registry");
    let foreign_session = foreign_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    assert_eq!(
        foreign_session.replay_snapshot(
            TenantId::from_bytes([0xef; 16]).expect("foreign tenant"),
            &snapshot,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::TenantConflict)
    );

    for corrupt in [
        SchemaCheckpointFrontier::new(
            known.shard(),
            known.position(),
            StoreBlockIdentity::new([0xe6; 16]).expect("identity"),
            known.digest(),
        )
        .expect("frontier"),
        SchemaCheckpointFrontier::new(
            known.shard(),
            known.position(),
            known.identity(),
            [0xe7; 32],
        )
        .expect("frontier"),
    ] {
        let bytes = schema
            .encode_checkpoint_object(&[corrupt])
            .expect("corrupt checkpoint remains structurally valid");
        let corrupt_registry = TenantSchemaRegistry::new(1).expect("registry");
        let session = corrupt_registry
            .session_from_checkpoint(fixture.tenant, &bytes, fixture.authority.governor())
            .expect("load checkpoint");
        assert_eq!(
            session.replay_snapshot(fixture.tenant, &snapshot, fixture.authority.governor()),
            Err(SchemaSessionFailure::ReplayIntegrity)
        );
    }
}

fn replay(
    fixture: &crate::tests::support::Fixture,
    snapshots: [&positron_kernel::LedgerSnapshot<'_>; 2],
    checkpoint: Option<&[u8]>,
    replay_first_twice: bool,
) -> Vec<u8> {
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = match checkpoint {
        Some(bytes) => {
            registry.session_from_checkpoint(fixture.tenant, bytes, fixture.authority.governor())
        },
        None => registry.session(fixture.tenant, fixture.authority.governor()),
    }
    .expect("session");
    for snapshot in snapshots {
        session
            .replay_snapshot(fixture.tenant, snapshot, fixture.authority.governor())
            .expect("replay");
    }
    let before = session
        .checkpoint()
        .expect("checkpoint")
        .catalog_bytes()
        .to_vec();
    if replay_first_twice {
        session
            .replay_snapshot(fixture.tenant, snapshots[0], fixture.authority.governor())
            .expect("idempotent replay");
        assert_eq!(
            session.checkpoint().expect("checkpoint").catalog_bytes(),
            before
        );
    }
    before
}

fn ingest<'authority>(
    fixture: &'authority crate::tests::support::Fixture,
    ledger: &ActiveSegmentLedger<'authority, '_>,
    shard: VirtualShardId,
    schema: super::super::TenantSchemaSession,
    marker: u8,
) {
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let policy = IngestPolicy::preserving(1).expect("policy");
    let batch = OtlpLogsReceiver::new()
        .decode(crate::tests::support::protobuf_request())
        .expect("OTLP");
    assert!(matches!(
        LogIngest::new(
            &fixture.authority,
            ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
            schema,
        )
        .accept(
            batch,
            StoreBlockIdentity::new([marker; 16]).expect("identity")
        ),
        IngestOutcome::Full(_)
    ));
}

fn ledger<'authority, 'catalog>(
    fixture: &'authority crate::tests::support::Fixture,
    catalog: &'catalog Catalog<'authority>,
    shard: VirtualShardId,
    marker: u8,
) -> ActiveSegmentLedger<'authority, 'catalog> {
    ActiveSegmentLedger::open(
        &fixture.authority,
        catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([marker; 32])),
    )
    .expect("ledger")
}
