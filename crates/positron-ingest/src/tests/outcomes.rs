use positron_domain::identity::TenantId;
use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    ByteLimit, RecordLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, AppendCancellation, Catalog, CatalogSecret, FixedLifecycleClockSource,
    InstanceId, LifecycleClock, LifecycleClockFailure, LifecycleClockSource, OrdinaryPool,
    ResourceAmounts, ResourceDimension, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
    WorkClaim, WorkKind,
};
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::{IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver};

use super::support::{fixture, protobuf_request, protobuf_with_bodies};

struct UnavailableLifecycleClock;

impl LifecycleClockSource for UnavailableLifecycleClock {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        Err(LifecycleClockFailure::Unavailable)
    }
}

struct CancellingLifecycleClock {
    cancellation: AppendCancellation,
    now: UnixNanoseconds,
}

impl LifecycleClockSource for CancellingLifecycleClock {
    fn read(&self) -> Result<UnixNanoseconds, LifecycleClockFailure> {
        self.cancellation.cancel();
        Ok(self.now)
    }
}

#[test]
fn schema_authority_mismatch_is_storage_unavailable_not_capacity() {
    let schema_fixture = fixture().expect("schema authority fixture");
    let ingest_fixture = fixture().expect("ingest authority fixture");
    let catalog = Catalog::open(
        &ingest_fixture.authority,
        InstanceId::new([0x51; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x52; 32]), Box::new([0x53; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(51).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &ingest_fixture.authority,
        &catalog,
        SegmentScope::new(ingest_fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x54; 32])),
    )
    .expect("ledger");
    let schema = super::support::schema_session(&schema_fixture).expect("schema session");
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_with_bodies(&["authority mismatch"]))
        .expect("batch");
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));

    assert_eq!(
        LogIngest::new(
            &ingest_fixture.authority,
            &ledger,
            &clock,
            &policy,
            ingest_fixture.tenant,
            shard,
            schema,
        )
        .accept(
            batch,
            StoreBlockIdentity::new([0x55; 16]).expect("identity"),
        ),
        IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable)
    );
}

#[test]
fn ingest_clock_refusal_is_retryable_and_rolls_back_schema_and_capacity() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x56; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x57; 32]), Box::new([0x58; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(52).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x59; 32])),
    )
    .expect("ledger");
    let schema = super::support::schema_session(&fixture).expect("schema session");
    let baseline = fixture
        .authority
        .governor()
        .inspect()
        .expect("baseline capacity");
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(UnavailableLifecycleClock);

    assert_eq!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
            schema.clone(),
        )
        .accept(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("batch"),
            StoreBlockIdentity::new([0x5a; 16]).expect("identity"),
        ),
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
    let checkpoint = schema.checkpoint().expect("rolled back checkpoint");
    assert_eq!(checkpoint.entry_count(), 0);
    assert_eq!(checkpoint.pending_bytes(), 0);
    assert_eq!(
        fixture.authority.governor().inspect().expect("released"),
        baseline
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
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        other_tenant,
        shard,
        super::support::schema_session(&fixture).expect("schema"),
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
        super::support::schema_session(&fixture).expect("schema"),
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
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
    let schema = super::support::schema_session(&fixture).expect("schema");
    let ingest = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
        schema.clone(),
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
    let checkpoint = schema.checkpoint().expect("checkpoint after cancellation");
    assert_eq!(checkpoint.entry_count(), 0);
    assert_eq!(checkpoint.overflow_record_count(), 0);
    assert_eq!(checkpoint.retained_charge_bytes(), 0);
    assert_eq!(checkpoint.pending_bytes(), 0);

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
fn cancellation_after_schema_staging_rolls_back_without_a_durable_prefix() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x68; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x69; 32]), Box::new([0x6a; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(62).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x6b; 32])),
    )
    .expect("ledger");
    let schema = super::support::schema_session(&fixture).expect("schema");
    let baseline = fixture.authority.governor().inspect().expect("baseline");
    let cancellation = AppendCancellation::new();
    let clock = LifecycleClock::new(CancellingLifecycleClock {
        cancellation: cancellation.clone(),
        now: UnixNanoseconds::new(2),
    });
    let policy = IngestPolicy::preserving(1).expect("policy");

    assert_eq!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
            schema.clone(),
        )
        .accept_cancellable(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("batch"),
            StoreBlockIdentity::new([0x6c; 16]).expect("identity"),
            &cancellation,
        ),
        IngestOutcome::Retryable(IngestFailureCode::Cancelled)
    );
    assert!(cancellation.is_cancelled());
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
    let checkpoint = schema.checkpoint().expect("rolled back checkpoint");
    assert_eq!(checkpoint.entry_count(), 0);
    assert_eq!(checkpoint.pending_bytes(), 0);
    let after = fixture.authority.governor().inspect().expect("released");
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
}

#[test]
fn snapshot_capacity_refusal_preserves_ingest_schema_and_governor_truth() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x88; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x89; 32]), Box::new([0x8a; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(82).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x8b; 32])),
    )
    .expect("ledger");
    let schema = super::support::schema_session(&fixture).expect("schema");
    let baseline = fixture.authority.governor().inspect().expect("baseline");
    let dimension = ResourceDimension::MemoryBytes;
    let query_bytes = baseline
        .pool_capacity(OrdinaryPool::Shared, dimension)
        .checked_sub(baseline.pool_usage(OrdinaryPool::Shared, dimension))
        .and_then(|shared| {
            baseline
                .pool_capacity(OrdinaryPool::InteractiveQueryTail, dimension)
                .checked_sub(baseline.pool_usage(OrdinaryPool::InteractiveQueryTail, dimension))
                .and_then(|query| shared.checked_add(query))
        })
        .and_then(|available| available.checked_sub(1))
        .expect("query capacity blocker");
    let blocker = fixture
        .authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                fixture.tenant,
                WorkKind::InteractiveQueryTail,
                ResourceAmounts::only(dimension, query_bytes).expect("bounded query claim"),
            )
            .expect("query claim"),
        )
        .expect("query blocker");
    let blocked = fixture.authority.governor().inspect().expect("blocked");
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));

    assert_eq!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            shard,
            schema.clone(),
        )
        .accept(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("batch"),
            StoreBlockIdentity::new([0x8c; 16]).expect("identity"),
        ),
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    let released = fixture.authority.governor().inspect().expect("released");
    assert_eq!(released.outstanding_total(), blocked.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(released.usage(dimension), blocked.usage(dimension));
    }
    assert_eq!(released.rejection_count(), blocked.rejection_count() + 1);
    let checkpoint = schema.checkpoint().expect("unchanged checkpoint");
    assert_eq!(checkpoint.entry_count(), 0);
    assert_eq!(checkpoint.pending_bytes(), 0);
    drop(blocker);
    assert!(
        ledger
            .snapshot()
            .expect("snapshot after release")
            .blocks()
            .is_empty()
    );
    let after = fixture.authority.governor().inspect().expect("baseline");
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
}

#[test]
fn physical_shard_mismatch_is_permanent_and_rolls_back_staged_schema() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x8d; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x8e; 32]), Box::new([0x8f; 32])),
    )
    .expect("catalog");
    let ledger_shard = VirtualShardId::new(83).expect("ledger shard");
    let ingest_shard = VirtualShardId::new(84).expect("ingest shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, ledger_shard),
        SegmentProtectionKey::from_owned(Box::new([0x90; 32])),
    )
    .expect("ledger");
    let schema = super::support::schema_session(&fixture).expect("schema");
    let baseline = fixture.authority.governor().inspect().expect("baseline");
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));

    assert_eq!(
        LogIngest::new(
            &fixture.authority,
            &ledger,
            &clock,
            &policy,
            fixture.tenant,
            ingest_shard,
            schema.clone(),
        )
        .accept(
            OtlpLogsReceiver::new()
                .decode(protobuf_request())
                .expect("batch"),
            StoreBlockIdentity::new([0x91; 16]).expect("identity"),
        ),
        IngestOutcome::Permanent(IngestFailureCode::InvalidRecord)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
    let checkpoint = schema.checkpoint().expect("rolled back checkpoint");
    assert_eq!(checkpoint.entry_count(), 0);
    assert_eq!(checkpoint.pending_bytes(), 0);
    let after = fixture.authority.governor().inspect().expect("after");
    assert_eq!(after.outstanding_total(), baseline.outstanding_total());
    for dimension in ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), baseline.usage(dimension));
    }
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
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(10)));
    let ingest = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
        super::support::schema_session(&fixture).expect("schema"),
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
    let policy = IngestPolicy::preserving(1).expect("policy");
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
                super::support::schema_session(&fixture).expect("schema"),
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
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(12)));

    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
        super::support::schema_session(&fixture).expect("schema"),
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
