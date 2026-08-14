use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, ResourceAmounts, ResourceDimension, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_policy::{IngestPolicy, PolicyEvaluation};
use positron_signals::{LogRecord, LogStore, SchemaBudget, SchemaCatalog, SchemaEntry};

use super::super::{DurableSchemaOutcome, SchemaSessionFailure, TenantSchemaRegistry};

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
            identity,
            first_shard,
            delta,
            Some(capacity),
            staged_bytes,
            DurableSchemaOutcome::Ambiguous { digest: [0xc8; 32] },
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
}

#[test]
fn committed_ambiguity_reconciles_from_v2_and_shrinks_to_exact_retained_charge() {
    let fixture = crate::tests::support::fixture().expect("fixture");
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
            reserve_memory(&fixture, 1_048_576),
            &LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100))),
            fixture.tenant,
            shard,
            identity,
            staged_records,
        )
        .expect("prepared v2 block")
        .into_store_block();
    let digest = block.content_digest().expect("digest");
    ledger.append(block).expect("durable append");
    session
        .resolve_durable_outcome(
            identity,
            shard,
            staged,
            Some(pending_capacity),
            staged_bytes,
            DurableSchemaOutcome::Ambiguous { digest },
        )
        .expect("pending ambiguity");
    assert_eq!(
        session.checkpoint().expect("pending").pending_bytes(),
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
            next_identity,
            shard,
            next,
            None,
            0,
            DurableSchemaOutcome::DefiniteFailure,
        )
        .expect("clear staged retry");
    let reconciled = session.checkpoint().expect("reconciled");
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
    ActiveSegmentLedger::open(
        &fixture.authority,
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
