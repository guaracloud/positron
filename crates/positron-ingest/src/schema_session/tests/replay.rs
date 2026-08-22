use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::CandidateAttributeValue;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_policy::IngestPolicy;
use positron_signals::{LogStore, ScanCancellation, SchemaCatalog, SchemaCheckpointFrontier};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::{SchemaSessionFailure, TenantSchemaRegistry};
use crate::{
    IngestOutcome, LogIngest, LogMetadata, NativeLogBatch, NativeLogCandidate, OtlpLogsReceiver,
    PolicyReceiver,
};

#[test]
fn rebuild_from_committed_custom_shards_is_canonical_and_idempotent() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
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

    let mut bootstrap =
        crate::SchemaReplayBuilder::new(fixture.tenant, None, fixture.authority.recovery())
            .expect("bootstrap replay");
    bootstrap
        .replay_snapshot(&first_snapshot)
        .expect("first bootstrap snapshot");
    bootstrap
        .replay_snapshot(&second_snapshot)
        .expect("second bootstrap snapshot");
    let bootstrap_left = bootstrap
        .finish()
        .expect("bootstrap checkpoint")
        .catalog_bytes()
        .to_vec();
    let mut reversed_bootstrap =
        crate::SchemaReplayBuilder::new(fixture.tenant, None, fixture.authority.recovery())
            .expect("reversed bootstrap replay");
    reversed_bootstrap
        .replay_snapshot(&second_snapshot)
        .expect("reversed second bootstrap snapshot");
    reversed_bootstrap
        .replay_snapshot(&first_snapshot)
        .expect("reversed first bootstrap snapshot");
    let bootstrap_right = reversed_bootstrap
        .finish()
        .expect("reversed bootstrap checkpoint")
        .catalog_bytes()
        .to_vec();
    assert_eq!(bootstrap_left, bootstrap_right);
    assert_ne!(bootstrap_left, expected);
}

#[test]
fn bootstrap_replay_keeps_mandatory_discovery_when_text_is_not_admitted() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd8; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xd9; 32]), Box::new([0xda; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(307).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xdb);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("live session");
    let live_view = live.clone();
    let body = "small body".to_owned();
    let decoded_bytes = u64::try_from(body.len()).expect("bounded body");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string(body)),
        Vec::new(),
        LogMetadata::empty(),
    );
    let batch = NativeLogBatch::new(
        crate::tests::support::attribution(),
        vec![candidate],
        LogStore::value_limit_profile(),
        decoded_bytes,
        None,
        PolicyReceiver::OtlpGrpc,
    )
    .expect("body-only batch");
    let policy = IngestPolicy::preserving(1).expect("policy");
    assert!(matches!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
            &policy,
            fixture.tenant,
            shard,
            live,
        )
        .accept(
            batch,
            StoreBlockIdentity::new([0xdc; 16]).expect("identity"),
        ),
        IngestOutcome::Full(_)
    ));
    let live_catalog = live_view
        .checkpoint()
        .expect("live checkpoint")
        .catalog_bytes()
        .to_vec();
    let snapshot = ledger.snapshot().expect("snapshot");
    drop(registry);

    let mut bootstrap =
        crate::SchemaReplayBuilder::new(fixture.tenant, None, fixture.authority.recovery())
            .expect("bootstrap replay");
    bootstrap
        .replay_snapshot(&snapshot)
        .expect("mandatory schema discovery survives omitted text evidence");
    let bootstrap_catalog = bootstrap
        .finish()
        .expect("bootstrap checkpoint")
        .catalog_bytes()
        .to_vec();
    assert!(!bootstrap_catalog.is_empty());
    assert!(
        bootstrap_catalog != live_catalog,
        "bootstrap omits optional text evidence when only mandatory work is admitted"
    );
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
    let foreign_tenant = TenantId::from_bytes([0xef; 16]).expect("foreign tenant");
    let foreign_fixture =
        crate::tests::support::fixture_for_tenant(foreign_tenant).expect("foreign fixture");
    assert!(matches!(
        TenantSchemaRegistry::new(1)
            .expect("registry")
            .session_from_checkpoint(
                foreign_tenant,
                &canonical,
                foreign_fixture.authority.governor(),
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

#[test]
fn replay_cancellation_does_not_publish_a_partial_frontier_or_catalog() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xf1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xf2; 32]), Box::new([0xf3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(304).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xf4);
    let live_registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = live_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    ingest(&fixture, &ledger, shard, live, 0xf5);
    let snapshot = ledger.snapshot().expect("snapshot");
    drop(live_registry);

    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    assert_eq!(
        session.with_catalog_view(TenantId::from_bytes([0x42; 16]).expect("tenant"), |_| ()),
        Err(SchemaSessionFailure::TenantConflict)
    );
    let before = session
        .checkpoint()
        .expect("empty checkpoint")
        .catalog_bytes()
        .to_vec();
    let cancellation = CancelAfterPolls::new(4);
    assert_eq!(
        session.replay_snapshot_cancellable(
            fixture.tenant,
            &snapshot,
            fixture.authority.governor(),
            &cancellation,
        ),
        Err(SchemaSessionFailure::Cancelled)
    );
    assert_eq!(
        session
            .checkpoint()
            .expect("checkpoint after cancellation")
            .catalog_bytes(),
        before
    );

    session
        .replay_snapshot(fixture.tenant, &snapshot, fixture.authority.governor())
        .expect("retry replay");
    assert_ne!(
        session
            .checkpoint()
            .expect("replayed checkpoint")
            .catalog_bytes(),
        before
    );
}

#[test]
fn replay_cancellation_on_later_block_is_atomic_for_catalog_frontier_and_capacity() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xa1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(305).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xa4);
    let live_registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = live_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    ingest(&fixture, &ledger, shard, live.clone(), 0xa5);
    ingest(&fixture, &ledger, shard, live, 0xa6);
    let expected = live_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("live session")
        .checkpoint()
        .expect("checkpoint")
        .catalog_bytes()
        .to_vec();
    let snapshot = ledger.snapshot().expect("snapshot");
    assert!(
        snapshot.blocks().len() >= 2,
        "test requires two committed blocks"
    );
    drop(live_registry);

    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let before_checkpoint_view = session.checkpoint().expect("empty checkpoint");
    let before_base_charge = before_checkpoint_view.base_charge_bytes();
    let before_checkpoint = before_checkpoint_view.catalog_bytes().to_vec();
    let before_governor = fixture.authority.governor().inspect().expect("governor");
    let cancellation = CancelAfterPolls::new(70);
    assert_eq!(
        session.replay_snapshot_cancellable(
            fixture.tenant,
            &snapshot,
            fixture.authority.governor(),
            &cancellation,
        ),
        Err(SchemaSessionFailure::Cancelled)
    );
    assert!(cancellation.poll_count() > 4, "must reach the later block");
    assert_eq!(
        session
            .checkpoint()
            .expect("checkpoint after cancellation")
            .catalog_bytes(),
        before_checkpoint
    );
    let after_governor = fixture.authority.governor().inspect().expect("governor");
    assert_eq!(
        after_governor.outstanding_total(),
        before_governor.outstanding_total()
    );
    assert_eq!(
        after_governor.outstanding_ordinary(),
        before_governor.outstanding_ordinary()
    );
    assert_eq!(
        after_governor.outstanding_recovery(),
        before_governor.outstanding_recovery()
    );
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(
            after_governor.usage(dimension),
            before_governor.usage(dimension),
            "governor usage leaked for {dimension:?}"
        );
    }

    session
        .replay_snapshot(fixture.tenant, &snapshot, fixture.authority.governor())
        .expect("retry replay");
    let replayed_checkpoint = session.checkpoint().expect("replayed checkpoint");
    assert_eq!(replayed_checkpoint.catalog_bytes(), expected);
    assert_eq!(replayed_checkpoint.base_charge_bytes(), before_base_charge);
    let after_success = fixture.authority.governor().inspect().expect("governor");
    let retained_memory = after_success
        .usage(positron_kernel::ResourceDimension::MemoryBytes)
        .checked_sub(before_governor.usage(positron_kernel::ResourceDimension::MemoryBytes))
        .expect("replay retained memory is monotonic");
    assert_eq!(retained_memory, replayed_checkpoint.retained_charge_bytes());
    for dimension in positron_kernel::ResourceDimension::ALL {
        let expected_usage = if dimension == positron_kernel::ResourceDimension::MemoryBytes {
            before_governor
                .usage(dimension)
                .checked_add(replayed_checkpoint.retained_charge_bytes())
                .expect("retained memory does not overflow")
        } else {
            before_governor.usage(dimension)
        };
        assert_eq!(
            after_success.usage(dimension),
            expected_usage,
            "resource drift for {dimension:?}"
        );
    }
    let stable_usage = after_success.usage(positron_kernel::ResourceDimension::MemoryBytes);
    session
        .replay_snapshot(fixture.tenant, &snapshot, fixture.authority.governor())
        .expect("idempotent replay");
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()
            .expect("governor")
            .usage(positron_kernel::ResourceDimension::MemoryBytes),
        stable_usage
    );
    drop(session);
    drop(registry);

    let mut bootstrap =
        crate::SchemaReplayBuilder::new(fixture.tenant, None, fixture.authority.recovery())
            .expect("bootstrap replay");
    let bootstrap_cancellation = CancelAfterPolls::new(70);
    assert_eq!(
        bootstrap.replay_snapshot_cancellable(&snapshot, &bootstrap_cancellation),
        Err(SchemaSessionFailure::Cancelled)
    );
    assert_eq!(
        bootstrap.replay_snapshot(&snapshot),
        Err(SchemaSessionFailure::StateUnavailable)
    );
    assert!(matches!(
        bootstrap.finish(),
        Err(SchemaSessionFailure::StateUnavailable)
    ));
}

#[test]
fn replay_preflight_admits_many_tiny_blocks_before_allocating_transaction_scratch() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xb1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(306).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xb4);
    let live_registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = live_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    for marker in 0xc0..0xc3 {
        ingest(&fixture, &ledger, shard, live.clone(), marker);
    }
    let snapshot = ledger.snapshot().expect("snapshot");
    assert_eq!(snapshot.blocks().len(), 3);
    drop(live);
    drop(live_registry);

    let registry = TenantSchemaRegistry::new(1).expect("replay registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("replay session");
    session
        .replay_snapshot(fixture.tenant, &snapshot, fixture.authority.governor())
        .expect("many tiny blocks replay");
    assert!(
        !session
            .checkpoint()
            .expect("replay checkpoint")
            .catalog_bytes()
            .is_empty()
    );
}

#[test]
fn reachable_index_collection_honors_cancellation_before_publication() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xb1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(306).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xb4);
    let live_registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = live_registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    ingest(&fixture, &ledger, shard, live, 0xb5);
    let snapshot = ledger.snapshot().expect("snapshot");
    drop(live_registry);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let cancellation = CancelAfterPolls::new(0);
    let observer = super::super::SchemaBuildObserver::new_scan(1, &cancellation);
    let mut reachable = Vec::new();

    assert_eq!(
        session.append_reachable_indexes_observed(
            &snapshot,
            &mut reachable,
            &cancellation,
            &observer,
        ),
        Err(SchemaSessionFailure::Cancelled)
    );
    assert!(reachable.is_empty());

    let observer_cancellation = CancelAfterPolls::new(1);
    let observer = super::super::SchemaBuildObserver::new_scan(1, &observer_cancellation);
    assert_eq!(
        session.append_reachable_indexes_observed(
            &snapshot,
            &mut reachable,
            &observer_cancellation,
            &observer,
        ),
        Err(SchemaSessionFailure::Cancelled)
    );

    let no_cancellation = CancelAfterPolls::new(usize::MAX);
    let observer = super::super::SchemaBuildObserver::new_scan(1, &no_cancellation);
    session
        .append_reachable_indexes_observed(&snapshot, &mut reachable, &no_cancellation, &observer)
        .expect("unverified blocks are skipped");
    assert!(reachable.is_empty());

    session
        .replay_snapshot(fixture.tenant, &snapshot, fixture.authority.governor())
        .expect("publish the verified block");
    let observer = super::super::SchemaBuildObserver::new_scan(u64::MAX, &no_cancellation);
    session
        .append_reachable_indexes_observed(&snapshot, &mut reachable, &no_cancellation, &observer)
        .expect("verified blocks are retained");
    assert_eq!(reachable.len(), 1);
    session
        .append_reachable_indexes_observed(&snapshot, &mut reachable, &no_cancellation, &observer)
        .expect("duplicate reachability is idempotent");
    assert_eq!(reachable.len(), 1);

    let cancelled = CancelAfterPolls::new(1);
    let observer = super::super::SchemaBuildObserver::new_scan(u64::MAX, &cancelled);
    assert_eq!(
        session.retain_reachable_indexes_observed(&[], &cancelled, &observer),
        Err(SchemaSessionFailure::Cancelled)
    );
    let immediately_cancelled = CancelAfterPolls::new(0);
    let observer = super::super::SchemaBuildObserver::new_scan(u64::MAX, &immediately_cancelled);
    assert_eq!(
        session.retain_reachable_indexes_observed(&[], &immediately_cancelled, &observer,),
        Err(SchemaSessionFailure::Cancelled)
    );
    let observer = super::super::SchemaBuildObserver::new_scan(0, &no_cancellation);
    assert!(matches!(
        session.retain_reachable_indexes_observed(&[], &no_cancellation, &observer),
        Err(SchemaSessionFailure::Schema(_))
    ));
}

#[test]
fn bootstrap_finish_observes_reachable_index_retention() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000).expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xb6; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xb7; 32]), Box::new([0xb8; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(308).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xb9);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let live = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    ingest(&fixture, &ledger, shard, live, 0xba);
    let snapshot = ledger.snapshot().expect("snapshot");
    drop(registry);

    let mut builder =
        crate::SchemaReplayBuilder::new(fixture.tenant, None, fixture.authority.recovery())
            .expect("bootstrap replay");
    builder.replay_snapshot(&snapshot).expect("replay snapshot");
    let no_cancellation = CancelAfterPolls::new(usize::MAX);
    let checkpoint = builder
        .finish_cancellable(&no_cancellation)
        .expect("finish after observed retention");
    assert!(!checkpoint.catalog_bytes().is_empty());
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

struct CancelAfterPolls {
    polls: AtomicUsize,
    cancel_after: usize,
}

impl CancelAfterPolls {
    const fn new(cancel_after: usize) -> Self {
        Self {
            polls: AtomicUsize::new(0),
            cancel_after,
        }
    }

    fn poll_count(&self) -> usize {
        self.polls.load(Ordering::Relaxed)
    }
}

impl ScanCancellation for CancelAfterPolls {
    fn is_cancelled(&self) -> bool {
        self.polls.fetch_add(1, Ordering::Relaxed) >= self.cancel_after
    }
}
