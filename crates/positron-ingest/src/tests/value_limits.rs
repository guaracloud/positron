use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_domain::value::{
    CollectionLimit, RequestLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, SegmentProtectionKey, SegmentScope, StoreBlockIdentity,
};

use crate::{IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver};

use super::support::{fixture, protobuf_with_bodies};

#[test]
fn lowered_request_record_limit_is_checked_after_policy_before_commit() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xc1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xc2; 32]), Box::new([0xc3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(121).expect("shard");
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xc4; 32])),
    )
    .expect("ledger");
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant_request = RequestLimits::new(
        maximum.request().compressed_bytes(),
        maximum.request().decompressed_bytes(),
        CollectionLimit::new(1).expect("fixture limit is nonzero"),
        maximum.request().aggregate_attributes(),
    );
    let tenant = ValueLimitSet::new(tenant_request, maximum.record(), maximum.dynamic_value());
    let profile = ValueLimitProfileCandidate::new(maximum, Some(tenant))
        .validate()
        .expect("tenant profile only lowers record count");
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(protobuf_with_bodies(&["first", "second"]))
        .expect("structural decode stays within hard safe maxima");
    let policy = IngestPolicy::preserving(1, [0xc5; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(13)));

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
        StoreBlockIdentity::new([0xc6; 16]).expect("identity"),
    );
    assert_eq!(
        outcome,
        IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
}

#[test]
fn lowered_request_attribute_limit_counts_namespaced_source_occurrences() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xd1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xd2; 32]), Box::new([0xd3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(131).expect("shard");
    let scope = SegmentScope::new(fixture.tenant, SignalKind::Logs, shard);
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        scope,
        SegmentProtectionKey::from_owned(Box::new([0xd4; 32])),
    )
    .expect("ledger");
    let maximum = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant_request = RequestLimits::new(
        maximum.request().compressed_bytes(),
        maximum.request().decompressed_bytes(),
        maximum.request().records(),
        CollectionLimit::new(1).expect("fixture limit is nonzero"),
    );
    let tenant = ValueLimitSet::new(tenant_request, maximum.record(), maximum.dynamic_value());
    let profile = ValueLimitProfileCandidate::new(maximum, Some(tenant))
        .validate()
        .expect("tenant profile only lowers aggregate attributes");
    let batch = OtlpLogsReceiver::with_value_limit_profile(profile)
        .decode(protobuf_with_bodies(&["one-record-two-attributes"]))
        .expect("resource and record attributes are structurally valid");
    let policy = IngestPolicy::preserving(1, [0xd5; 32]).expect("policy");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(14)));

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
        StoreBlockIdentity::new([0xd6; 16]).expect("identity"),
    );
    assert_eq!(
        outcome,
        IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());
}
