use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_signals::{LogScan, LogStore, ScanLimit, SchemaBudget, SchemaCatalog};

use crate::{IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver};

use super::support::{fixture, protobuf_request, schema_session};

#[test]
fn durable_outcome_carries_the_kernel_receipt_and_is_readable_through_the_log_store() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x18; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x28; 32]), Box::new([0x38; 32])),
    )
    .expect("catalog");
    let tenant = fixture.tenant;
    let shard = VirtualShardId::new(8).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x58; 32])),
    )
    .expect("ledger");
    let store = LogStore::new();
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(100)));
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_request())
        .expect("valid OTLP");

    let policy = IngestPolicy::preserving(1).expect("policy");
    let schema = schema_session(&fixture).expect("schema session");
    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        tenant,
        shard,
        schema.clone(),
    )
    .accept(
        batch,
        StoreBlockIdentity::new([0x68; 16]).expect("block identity"),
    );
    let receipt = match outcome {
        IngestOutcome::Full(committed) => committed.receipt(),
        other => panic!("expected durable full outcome, got {other:?}"),
    };
    assert_eq!(receipt.position().value(), 1);

    let result = store
        .scan(
            fixture.authority.governor(),
            tenant,
            &ledger.snapshot().expect("snapshot"),
            LogScan::all(ScanLimit::new(1).expect("scan limit")),
        )
        .expect("readback");
    assert_eq!(result.records().len(), 1);
    assert_eq!(
        result.records()[0].body().and_then(|body| body.as_str()),
        Some("paid")
    );
    let checkpoint = schema.checkpoint().expect("checkpoint");
    assert!(checkpoint.entry_count() > 0);
    let discovered = SchemaCatalog::decode_catalog_object(checkpoint.catalog_bytes())
        .expect("checkpoint catalog");
    let empty = SchemaCatalog::new(tenant, SchemaBudget::release_1().expect("budget"))
        .expect("empty catalog");
    let exact_growth = discovered
        .memory_bytes()
        .checked_sub(empty.memory_bytes())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .expect("retained growth");
    assert_eq!(checkpoint.retained_charge_bytes(), exact_growth);
    assert_eq!(checkpoint.pending_bytes(), 0);
}
