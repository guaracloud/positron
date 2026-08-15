use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};
use positron_signals::{LogScan, LogStore, ScanLimit};

use crate::{
    IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver, PolicyAction,
    PolicyPredicate, PolicyRule, PolicyTarget,
};

#[test]
fn release_one_default_policy_has_one_canonical_non_placeholder_snapshot() {
    let policy = IngestPolicy::release_1_default().expect("default policy");
    assert_eq!(policy.provenance().generation(), 1);
    assert_ne!(policy.provenance().digest(), [1_u8; 32]);
    assert!(policy.provenance().applied_rules().is_empty());
}

use super::support::{fixture, protobuf_with_bodies};

#[test]
fn policy_rejection_precedes_value_limits_and_partial_requires_a_receipt() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x71; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x72; 32]), Box::new([0x73; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(71).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x74; 32])),
    )
    .expect("ledger");
    let oversized_rejected = "x".repeat(262_145);
    let request = protobuf_with_bodies(&[oversized_rejected.as_str(), "accepted"]);
    let batch = OtlpLogsReceiver::new()
        .decode(request)
        .expect("structural decode");
    let policy = IngestPolicy::reject_exact_text_body(7, "reject-oversized", &oversized_rejected)
        .expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(200)));

    let partial = match LogIngest::new(
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
        StoreBlockIdentity::new([0x76; 16]).expect("identity"),
    ) {
        IngestOutcome::Partial(partial) => partial,
        other => panic!("expected partial result, got {other:?}"),
    };
    assert_eq!(partial.committed().records(), 1);
    assert_eq!(partial.permanently_rejected(), 1);
    assert_eq!(partial.committed().receipt().position().value(), 1);

    let result = LogStore::new()
        .scan(
            fixture.authority.governor(),
            fixture.tenant,
            &ledger.snapshot().expect("snapshot"),
            LogScan::all(ScanLimit::new(2).expect("limit")),
        )
        .expect("scan");
    assert_eq!(result.records().len(), 1);
    assert_eq!(
        result.records()[0].body().and_then(|body| body.as_str()),
        Some("accepted")
    );
    assert_eq!(result.records()[0].policy_provenance().generation(), 7);
    assert_eq!(
        result.records()[0].policy_provenance().applied_rules(),
        &[] as &[String]
    );
}

#[test]
fn later_predicates_observe_prior_ordered_transformations() {
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_with_bodies(&["12345"]))
        .expect("decode");
    let (_, mut records, _, _, receiver) = batch.into_parts();
    let policy = IngestPolicy::compile(
        8,
        vec![
            PolicyRule::new(
                "truncate",
                Vec::new(),
                PolicyAction::TruncateBytes(PolicyTarget::body(), 4),
            )
            .expect("truncate rule"),
            PolicyRule::new(
                "reject-truncated",
                vec![PolicyPredicate::body_exact_text("1234").expect("predicate")],
                PolicyAction::Reject,
            )
            .expect("reject rule"),
        ],
    )
    .expect("policy");
    assert!(matches!(
        policy.evaluate(records.remove(0), receiver),
        Ok(crate::PolicyEvaluation::Rejected)
    ));
}

#[test]
fn partial_admission_preserves_each_permanent_rejection_class() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x41; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x42; 32]), Box::new([0x43; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(41).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x44; 32])),
    )
    .expect("ledger");
    let oversized = "x".repeat(262_145);
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_with_bodies(&[
            "reject-me",
            oversized.as_str(),
            "accepted",
        ]))
        .expect("structural decode");
    let policy = IngestPolicy::reject_exact_text_body(3, "reject", "reject-me").expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(3)));
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
        StoreBlockIdentity::new([0x46; 16]).expect("identity"),
    );
    let partial = match outcome {
        IngestOutcome::Partial(partial) => partial,
        other => panic!("expected partial, got {other:?}"),
    };
    assert_eq!(partial.permanently_rejected(), 2);
    assert_eq!(
        partial
            .rejections()
            .iter()
            .map(|detail| (detail.code(), detail.records()))
            .collect::<Vec<_>>(),
        vec![
            (IngestFailureCode::PolicyRejected, 1),
            (IngestFailureCode::ValueLimitExceeded, 1),
        ]
    );
}

#[test]
fn value_limit_rejection_never_claims_durability() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x77; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x78; 32]), Box::new([0x79; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(72).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x7a; 32])),
    )
    .expect("ledger");
    let oversized = "x".repeat(262_145);
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_with_bodies(&[oversized.as_str()]))
        .expect("structural decode");
    let policy = IngestPolicy::preserving(1).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(200)));
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
            batch,
            StoreBlockIdentity::new([0x7c; 16]).expect("identity")
        ),
        IngestOutcome::Permanent(crate::IngestFailureCode::ValueLimitExceeded)
    ));
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
}

#[test]
fn complete_policy_rejection_is_permanent_and_has_no_receipt() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x7d; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x7e; 32]), Box::new([0x7f; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(73).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0x80; 32])),
    )
    .expect("ledger");
    let batch = OtlpLogsReceiver::new()
        .decode(protobuf_with_bodies(&["reject-me"]))
        .expect("decode");
    let policy = IngestPolicy::reject_exact_text_body(2, "reject", "reject-me").expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(200)));
    assert_eq!(
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
            batch,
            StoreBlockIdentity::new([0x82; 16]).expect("identity"),
        ),
        IngestOutcome::Permanent(crate::IngestFailureCode::PolicyRejected)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
}
