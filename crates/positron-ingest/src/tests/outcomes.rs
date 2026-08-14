use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    ByteLimit, RecordLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, Catalog, CatalogSecret, FixedLifecycleClockSource,
    InstanceId, LifecycleClock, ResourceAmounts, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity, WorkClaim, WorkKind,
};
use positron_signals::{LogScan, LogStore, LogStoreFailureCode, ScanLimit};

use crate::{IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver};

use super::support::{fixture, protobuf_request, protobuf_with_bodies};

#[test]
fn log_store_allocation_failure_remains_retryable_at_ingest_boundary() {
    assert_eq!(
        crate::ingest::classify_log_store_failure_code(LogStoreFailureCode::ResourceExhausted),
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert_eq!(
        crate::ingest::classify_log_store_failure_code(LogStoreFailureCode::LimitExceeded),
        IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
    );
}

#[test]
fn attributed_batch_cannot_cross_the_admission_group_tenant() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x61; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x62; 32]), Box::new([0x63; 32])),
    )
    .expect("catalog");
    let other_tenant = TenantId::from_bytes([3; 16]).expect("tenant");
    let shard = VirtualShardId::new(61).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x64; 32])),
    )
    .expect("ledger");
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_request())
        .expect("batch");
    let policy = IngestPolicy::preserving(1, [0x65; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        other_tenant,
        shard,
    )
    .accept(
        batch,
        StoreBlockIdentity::new([0x66; 16]).expect("identity"),
    );
    assert_eq!(
        outcome,
        IngestOutcome::Permanent(IngestFailureCode::TenantConflict)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());

    let correct_ingest = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
    );
    let empty = correct_ingest.accept(
        OtlpLogsReceiver::new()
            .decode(protobuf_with_bodies(&[]))
            .expect("empty structural batch"),
        StoreBlockIdentity::new([0x67; 16]).expect("identity"),
    );
    assert_eq!(
        empty,
        IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
    );
    assert_eq!(empty.producer_disconnected_after_commit(), empty);
}

#[test]
fn cancellation_and_capacity_refusal_are_retryable_and_release_reservations() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x81; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x82; 32]), Box::new([0x83; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(81).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x84; 32])),
    )
    .expect("ledger");
    let policy = IngestPolicy::preserving(1, [0x85; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
    let ingest = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
    );
    let baseline = fixture
        .authority
        .governor()
        .inspect()
        .expect("baseline")
        .outstanding_total();
    let cancellation = AppendCancellation::new();
    cancellation.cancel();
    assert_eq!(
        ingest.accept_cancellable(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("batch"),
            StoreBlockIdentity::new([0x86; 16]).expect("identity"),
            &cancellation,
        ),
        IngestOutcome::Retryable(IngestFailureCode::Cancelled)
    );
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()
            .expect("after cancel")
            .outstanding_total(),
        baseline
    );

    let amounts = ResourceAmounts::new([1_048_576, 1, 1, 1_048_576, 1, 0, 1, 1, 1, 4, 1_048_576]);
    let claim = WorkClaim::tenant(fixture.tenant, WorkKind::Ingest, amounts).expect("claim");
    let mut held = Vec::new();
    while let Ok(reservation) = fixture.authority.governor().reserve(claim) {
        held.push(reservation);
    }
    assert!(!held.is_empty());
    assert_eq!(
        ingest.accept(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("batch"),
            StoreBlockIdentity::new([0x87; 16]).expect("identity"),
        ),
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
    drop(held);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()
            .expect("after capacity release")
            .outstanding_total(),
        baseline
    );
}

#[test]
fn post_commit_disconnect_is_ambiguous_while_retry_replays_one_durable_block() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x91; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x92; 32]), Box::new([0x93; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(91).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x94; 32])),
    )
    .expect("ledger");
    let policy = IngestPolicy::preserving(1, [0x95; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(10)));
    let ingest = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
    );
    let identity = StoreBlockIdentity::new([0x96; 16]).expect("identity");
    let first = ingest.accept(
        OtlpLogsReceiver::new()
            .decode(protobuf_request())
            .expect("batch"),
        identity,
    );
    let first_receipt = match first {
        IngestOutcome::Full(committed) => committed.receipt(),
        other => panic!("expected commit, got {other:?}"),
    };
    assert_eq!(
        first.producer_disconnected_after_commit(),
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
    );

    let retry = ingest.accept(
        OtlpLogsReceiver::new()
            .decode(protobuf_request())
            .expect("retry batch"),
        identity,
    );
    let retry_receipt = match retry {
        IngestOutcome::Full(committed) => committed.receipt(),
        other => panic!("expected idempotent replay, got {other:?}"),
    };
    assert_eq!(retry_receipt, first_receipt);
    assert_eq!(ledger.snapshot().expect("snapshot").blocks().len(), 1);

    assert_eq!(
        ingest.accept(
            OtlpLogsReceiver::new()
                .decode(protobuf_with_bodies(&["changed"]))
                .expect("changed retry batch"),
            identity,
        ),
        IngestOutcome::Permanent(IngestFailureCode::IdempotencyConflict)
    );
    assert!(matches!(
        ingest.accept(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("legitimate duplicate batch"),
            StoreBlockIdentity::new([0x97; 16]).expect("distinct identity"),
        ),
        IngestOutcome::Full(_)
    ));
    assert_eq!(ledger.snapshot().expect("snapshot").blocks().len(), 2);
}

#[test]
fn committed_logs_survive_reopen_and_remain_publicly_readable() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xa1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xa2; 32]), Box::new([0xa3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(101).expect("shard");
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let policy = IngestPolicy::preserving(1, [0xa4; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(11)));
    {
        let ledger = ActiveSegmentLedger::open(
            &fixture.authority,
            &catalog,
            scope,
            SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
        )
        .expect("ledger");
        assert!(matches!(
            LogIngest::new(
                &fixture.authority,
                &ledger,
                &clock,
                &policy,
                fixture.tenant,
                shard,
            )
            .accept(
                OtlpLogsReceiver::new()
                    .decode(protobuf_request())
                    .expect("batch"),
                StoreBlockIdentity::new([0xa6; 16]).expect("identity"),
            ),
            IngestOutcome::Full(_)
        ));
    }

    let reopened = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xa5; 32])),
    )
    .expect("restart recovery");
    let result = LogStore::new()
        .scan(
            fixture.authority.governor(),
            fixture.tenant,
            &reopened.snapshot().expect("snapshot"),
            LogScan::all(ScanLimit::new(1).expect("limit")),
        )
        .expect("readback");
    assert_eq!(result.records().len(), 1);
    assert_eq!(
        result.records()[0].body().and_then(|body| body.as_str()),
        Some("paid")
    );
}

#[test]
fn receiver_profile_snapshot_governs_post_policy_log_validation() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xb1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xb2; 32]), Box::new([0xb3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(111).expect("shard");
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xb4; 32])),
    )
    .expect("ledger");
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant_record = RecordLimits::new(
        maximum.record().encoded_bytes(),
        maximum.record().decoded_bytes(),
        ByteLimit::new(4).expect("fixture limit is nonzero"),
    );
    let tenant = ValueLimitSet::new(maximum.request(), tenant_record, maximum.dynamic_value());
    let profile = ValueLimitProfileCandidate::new(maximum, Some(tenant))
        .validate()
        .expect("tenant profile lowers only the body limit");
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(protobuf_with_bodies(&["12345"]))
        .expect("structural decode uses the safe system maximum before policy");
    let policy = IngestPolicy::preserving(1, [0xb5; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(12)));

    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
    )
    .accept(
        batch,
        StoreBlockIdentity::new([0xb6; 16]).expect("identity"),
    );
    assert_eq!(
        outcome,
        IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
}
