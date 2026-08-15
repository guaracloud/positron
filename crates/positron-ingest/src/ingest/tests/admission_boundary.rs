use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_domain::time::UnixNanoseconds;
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, FixedLifecycleClockSource, InstanceId,
    LifecycleClock, ResourceAmounts, ResourceDimension, SegmentProtectionKey, SegmentScope,
    StoreBlockIdentity, WorkClaim, WorkKind,
};

use crate::{IngestFailureCode, IngestOutcome, IngestPolicy, LogIngest, OtlpLogsReceiver};

use super::super::{group_work_amounts, schema_admission_estimate};

const ORDINARY_MEMORY_BYTES: u64 = 8_000_000;

#[test]
fn exact_schema_aware_capacity_reaches_policy_and_one_byte_under_refuses_first() {
    assert_eq!(
        run_at_boundary(0),
        IngestOutcome::Permanent(IngestFailureCode::PolicyRejected)
    );
    assert_eq!(
        run_at_boundary(1),
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
}

fn run_at_boundary(shortage: u64) -> IngestOutcome {
    let fixture = crate::tests::support::fixture_with_ordinary_memory(ORDINARY_MEMORY_BYTES)
        .expect("fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0xe1; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0xe2; 32]), Box::new([0xe3; 32])),
    )
    .expect("catalog");
    let shard = VirtualShardId::new(225).expect("shard");
    let ledger = ActiveSegmentLedger::open(
        &fixture.authority,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, shard),
        SegmentProtectionKey::from_owned(Box::new([0xe4; 32])),
    )
    .expect("ledger");
    let schema = crate::tests::support::schema_session(&fixture).expect("schema");
    let rejected = "x".repeat(262_145);
    let batch = OtlpLogsReceiver::new()
        .decode(crate::tests::support::protobuf_with_bodies(&[
            rejected.as_str()
        ]))
        .expect("batch");
    let policy = IngestPolicy::reject_exact_text_body(1, "reject", &rejected).expect("policy");
    let estimate = schema_admission_estimate(batch.records()).expect("estimate");
    let count = u64::try_from(batch.records().len()).expect("count");
    let group = group_work_amounts(count, policy.budget(), estimate).expect("group amounts");
    let required = group
        .get(ResourceDimension::MemoryBytes)
        .checked_add(estimate.retained_memory_bytes())
        .expect("combined reservation");
    let probe = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, ORDINARY_MEMORY_BYTES)
            .expect("probe amounts"),
    )
    .expect("probe claim");
    let refusal = match fixture.authority.governor().reserve(probe) {
        Ok(_) => panic!("lifetime state must consume part of the tenant allowance"),
        Err(failure) => failure,
    };
    assert_eq!(
        refusal.limiting_dimension(),
        Some(ResourceDimension::MemoryBytes)
    );
    assert_eq!(refusal.allowed(), ORDINARY_MEMORY_BYTES);
    let protected_available = refusal
        .allowed()
        .checked_sub(refusal.in_use())
        .expect("available memory");
    let class_probe = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, protected_available)
            .expect("class probe amounts"),
    )
    .expect("class probe claim");
    let class_refusal = match fixture.authority.governor().reserve(class_probe) {
        Ok(_) => panic!("class headroom must remain protected"),
        Err(failure) => failure,
    };
    assert_eq!(
        class_refusal.limiting_dimension(),
        Some(ResourceDimension::MemoryBytes)
    );
    let class_available = class_refusal
        .allowed()
        .checked_sub(class_refusal.in_use())
        .expect("class available memory");
    let filler_bytes = protected_available
        .min(class_available)
        .checked_sub(required)
        .and_then(|bytes| bytes.checked_add(shortage))
        .expect("fixture covers exact admission");
    let filler = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, filler_bytes).expect("filler"),
    )
    .expect("filler claim");
    let _held = fixture
        .authority
        .governor()
        .reserve(filler)
        .expect("boundary filler");
    let clock = LifecycleClock::new(FixedLifecycleClockSource::new(UnixNanoseconds::new(1)));
    LogIngest::new(
        &fixture.authority,
        &ledger,
        &clock,
        &policy,
        fixture.tenant,
        shard,
        schema,
    )
    .accept(
        batch,
        StoreBlockIdentity::new([0xe5; 16]).expect("identity"),
    )
}
