use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, ResourceAmounts, ResourceDimension,
    RetentionTimeAuthority, SegmentProtectionKey, SegmentScope, StoreBlockIdentity, WorkClaim,
    WorkKind,
};
use positron_policy::{IngestPolicy, PolicyEvaluation};
use positron_signals::{LogRecord, LogStore, SchemaBudget, SchemaCatalog, SchemaEntry};

use super::super::{
    DurableSchemaOutcome, DurableSchemaResolution, SchemaSessionFailure, TenantSchemaRegistry,
};

#[test]
fn ambiguous_delta_retains_one_exact_bounded_reservation_until_reconciliation() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xc1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )
    .expect("catalog");
    let first_shard = VirtualShardId::new(201).expect("shard");
    let other_shard = VirtualShardId::new(202).expect("shard");
    let first_ledger = ledger(&fixture, &catalog, first_shard, 0xc4);
    let other_ledger = ledger(&fixture, &catalog, other_shard, 0xc5);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let identity = StoreBlockIdentity::new([0xc6; 16]).expect("identity");
    let mut staged_records = records();
    let delta = session
        .stage_group(
            fixture.tenant,
            first_shard,
            identity,
            &first_ledger.snapshot().expect("snapshot"),
            &mut staged_records,
            fixture.authority.governor(),
        )
        .expect("stage");
    let staged_bytes = u64::try_from(delta.staged_memory_bytes()).expect("bounded bytes");
    assert!(staged_bytes > 0);
    let claim = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, staged_bytes).expect("amounts"),
    )
    .expect("claim");
    let capacity = fixture
        .authority
        .governor()
        .reserve(claim)
        .expect("pending capacity")
        .transfer();
    session
        .resolve_durable_outcome(
            DurableSchemaResolution {
                identity,
                shard: first_shard,
                staged: delta,
                capacity: Some(capacity),
                capacity_bytes: staged_bytes,
                outcome: DurableSchemaOutcome::Ambiguous { digest: [0xc8; 32] },
            },
            fixture.authority.governor(),
        )
        .expect("ambiguous state");

    let checkpoint = session.checkpoint().expect("checkpoint");
    assert_eq!(checkpoint.pending_bytes(), staged_bytes);
    assert_eq!(checkpoint.retained_charge_bytes(), 0);
    assert_eq!(checkpoint.entry_count(), 0);
    assert!(staged_bytes <= maximum_staged_delta_bytes());

    let mut retry = records();
    assert!(matches!(
        session.stage_group(
            fixture.tenant,
            other_shard,
            StoreBlockIdentity::new([0xc7; 16]).expect("identity"),
            &other_ledger.snapshot().expect("snapshot"),
            &mut retry,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::PendingReconciliationRequired)
    ));
    assert_eq!(
        session.checkpoint().expect("pending").pending_bytes(),
        staged_bytes
    );
    assert!(
        !session
            .has_checkpoint_changes()
            .expect("pending state remains unpublished")
    );

    let mut same_shard_retry = records();
    assert!(matches!(
        session.stage_group(
            fixture.tenant,
            first_shard,
            StoreBlockIdentity::new([0xc9; 16]).expect("identity"),
            &first_ledger.snapshot().expect("empty snapshot"),
            &mut same_shard_retry,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::PendingReconciliationRequired)
    ));
    assert_eq!(
        session.checkpoint().expect("pending").pending_bytes(),
        staged_bytes
    );
}

#[test]
fn committed_ambiguity_reconciles_from_v2_and_shrinks_to_exact_retained_charge() {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(40_000_000)
        .expect("replay-capable fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(203).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xd4);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let identity = StoreBlockIdentity::new([0xd5; 16]).expect("identity");
    let mut staged_records = records();
    let staged = session
        .stage_group(
            fixture.tenant,
            shard,
            identity,
            &ledger.snapshot().expect("empty snapshot"),
            &mut staged_records,
            fixture.authority.governor(),
        )
        .expect("stage");
    let staged_bytes = u64::try_from(staged.staged_memory_bytes()).expect("bounded staging");
    let pending_capacity = reserve_memory(&fixture, staged_bytes).transfer();
    let block = LogStore::new()
        .prepare(
            ledger
                .begin_store_block(reserve_memory(&fixture, 1_048_576), identity)
                .expect("kernel preparation"),
            staged_records,
        )
        .expect("prepared v2 block")
        .into_store_block();
    let digest = block.content_digest().expect("digest");
    ledger.append(block).expect("durable append");
    session
        .resolve_durable_outcome(
            DurableSchemaResolution {
                identity,
                shard,
                staged,
                capacity: Some(pending_capacity),
                capacity_bytes: staged_bytes,
                outcome: DurableSchemaOutcome::Ambiguous { digest },
            },
            fixture.authority.governor(),
        )
        .expect("pending ambiguity");
    assert_eq!(
        session.checkpoint().expect("pending").pending_bytes(),
        staged_bytes
    );

    let foreign = crate::tests::support::fixture_for_tenant(fixture.tenant).expect("foreign");
    let mut refused_records = records();
    assert!(matches!(
        session.stage_group(
            fixture.tenant,
            shard,
            StoreBlockIdentity::new([0xda; 16]).expect("identity"),
            &ledger.snapshot().expect("committed snapshot"),
            &mut refused_records,
            foreign.authority.governor(),
        ),
        Err(SchemaSessionFailure::StateUnavailable)
    ));
    assert_eq!(
        session
            .checkpoint()
            .expect("pending retained")
            .pending_bytes(),
        staged_bytes
    );

    let next_identity = StoreBlockIdentity::new([0xd6; 16]).expect("identity");
    let mut next_records = records();
    let next = session
        .stage_group(
            fixture.tenant,
            shard,
            next_identity,
            &ledger.snapshot().expect("committed snapshot"),
            &mut next_records,
            fixture.authority.governor(),
        )
        .expect("reconciliation uses committed v2 block");
    session
        .resolve_durable_outcome(
            DurableSchemaResolution {
                identity: next_identity,
                shard,
                staged: next,
                capacity: None,
                capacity_bytes: 0,
                outcome: DurableSchemaOutcome::DefiniteFailure,
            },
            fixture.authority.governor(),
        )
        .expect("clear staged retry");
    let reconciled = session.checkpoint().expect("reconciled");
    assert!(
        session
            .has_checkpoint_changes()
            .expect("reconciliation changed checkpoint state")
    );
    let catalog = SchemaCatalog::decode_catalog_object(reconciled.catalog_bytes())
        .expect("reconciled catalog");
    let empty = SchemaCatalog::new(fixture.tenant, SchemaBudget::release_1().expect("budget"))
        .expect("empty catalog");
    let exact = u64::try_from(
        catalog
            .memory_bytes()
            .checked_sub(empty.memory_bytes())
            .expect("catalog growth"),
    )
    .expect("bounded growth");
    assert_eq!(reconciled.pending_bytes(), 0);
    assert_eq!(reconciled.retained_charge_bytes(), exact);
    assert!(exact > 0);
    assert!(exact < staged_bytes);
}

#[test]
fn committed_resolution_capacity_failure_retains_exact_pending_state() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xa1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(204).expect("shard");
    let ledger = ledger(&fixture, &catalog, shard, 0xa4);
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let session = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let identity = StoreBlockIdentity::new([0xa5; 16]).expect("identity");
    let mut staged_records = records();
    let delta = session
        .stage_group(
            fixture.tenant,
            shard,
            identity,
            &ledger.snapshot().expect("snapshot"),
            &mut staged_records,
            fixture.authority.governor(),
        )
        .expect("stage");
    let retained = u64::try_from(delta.retained_memory_bytes()).expect("retained");
    let capacity = reserve_memory(&fixture, retained).transfer();
    let foreign = crate::tests::support::fixture_for_tenant(fixture.tenant).expect("foreign");

    assert_eq!(
        session.resolve_durable_outcome(
            DurableSchemaResolution {
                identity,
                shard,
                staged: delta,
                capacity: Some(capacity),
                capacity_bytes: retained,
                outcome: DurableSchemaOutcome::Committed {
                    position: positron_domain::routing::CommitPosition::origin()
                        .advance_by(std::num::NonZeroU64::new(1).expect("nonzero"))
                        .expect("position"),
                    digest: [0xa6; 32],
                },
            },
            foreign.authority.governor(),
        ),
        Err(SchemaSessionFailure::StateUnavailable)
    );
    let checkpoint = session.checkpoint().expect("pending checkpoint");
    assert_eq!(checkpoint.entry_count(), 0);
    assert_eq!(checkpoint.pending_bytes(), retained);

    let mut retry = records();
    assert!(matches!(
        session.stage_group(
            fixture.tenant,
            shard,
            StoreBlockIdentity::new([0xa7; 16]).expect("identity"),
            &ledger.snapshot().expect("empty snapshot"),
            &mut retry,
            fixture.authority.governor(),
        ),
        Err(SchemaSessionFailure::PendingReconciliationRequired)
    ));
    assert_eq!(
        session.checkpoint().expect("still pending").pending_bytes(),
        retained
    );
}

fn reserve_memory<'fixture>(
    fixture: &'fixture crate::tests::support::Fixture,
    bytes: u64,
) -> positron_kernel::ResourceReservation<'fixture> {
    fixture
        .authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                fixture.tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes).expect("amounts"),
            )
            .expect("claim"),
        )
        .expect("capacity")
}

fn records() -> Vec<LogRecord> {
    let batch = crate::OtlpLogsReceiver::new()
        .decode(crate::tests::support::protobuf_request())
        .expect("batch");
    let (_, candidates, profile, _, receiver) = batch.into_parts();
    let policy = IngestPolicy::preserving(1).expect("policy");
    candidates
        .into_iter()
        .map(
            |candidate| match policy.evaluate(candidate, receiver).expect("policy") {
                PolicyEvaluation::Accepted(record) => {
                    LogRecord::checked_evaluated(profile, *record).expect("record")
                },
                PolicyEvaluation::Rejected => panic!("preserving policy rejected"),
            },
        )
        .collect()
}

fn ledger<'authority, 'catalog>(
    fixture: &'authority crate::tests::support::Fixture,
    catalog: &'catalog Catalog<'authority>,
    shard: VirtualShardId,
    marker: u8,
) -> ActiveSegmentLedger<'authority, 'catalog> {
    let retention_time = Box::leak(Box::new(
        RetentionTimeAuthority::establish().expect("retention time"),
    ));
    ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        retention_time,
        catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([marker; 32])),
    )
    .expect("ledger")
}

fn maximum_staged_delta_bytes() -> u64 {
    let slots = SchemaBudget::system_max_entries()
        .checked_mul(std::mem::size_of::<SchemaEntry>())
        .expect("bounded slots");
    u64::try_from(
        SchemaBudget::system_max_memory_bytes()
            .checked_add(slots)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<SchemaEntry>>()))
            .expect("bounded maximum"),
    )
    .expect("bounded maximum")
}
