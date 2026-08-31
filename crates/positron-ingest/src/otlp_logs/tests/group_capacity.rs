use positron_domain::routing::{SignalKind, VirtualShardId};
use positron_kernel::{
    ActiveSegmentLedger, Catalog, CatalogSecret, InstanceId, ResourceAmounts, SegmentProtectionKey,
    SegmentScope, StoreBlockIdentity, WorkClaim, WorkKind,
};

use super::super::NativeLogCandidate;
use crate::tests::support::{fixture, protobuf_with_bodies};
use crate::{
    AdmissionGroupPlanFailure, AdmissionGroupPlanner, IngestFailureCode, IngestOutcome,
    IngestPolicy, LogIngest, OtlpLogsReceiver,
};

struct TwoShardPlan;

impl AdmissionGroupPlanner for TwoShardPlan {
    fn assigned_shard(
        &self,
        _tenant: positron_domain::identity::TenantId,
        _signal: SignalKind,
        record_ordinal: u32,
        _record: &NativeLogCandidate,
    ) -> Result<VirtualShardId, AdmissionGroupPlanFailure> {
        VirtualShardId::new(record_ordinal.saturating_add(1))
            .map_err(|_| AdmissionGroupPlanFailure::AssignmentUnavailable)
    }
}

#[test]
fn second_group_capacity_is_reserved_before_its_configured_policy_result() {
    let fixture = fixture().expect("kernel fixture");
    let catalog = Catalog::open(
        &fixture.authority,
        InstanceId::new([0x31; 16]).expect("instance"),
        CatalogSecret::from_owned(Box::new([0x32; 32]), Box::new([0x33; 32])),
    )
    .expect("catalog");
    let second_shard = VirtualShardId::new(2).expect("second shard");
    let ledger = ActiveSegmentLedger::open_with_retention_time(
        &fixture.authority,
        &fixture.retention_time,
        &catalog,
        SegmentScope::new(fixture.tenant, SignalKind::Logs, second_shard),
        SegmentProtectionKey::from_owned(Box::new([0x34; 32])),
    )
    .expect("ledger");
    let baseline = fixture
        .authority
        .governor()
        .inspect()
        .expect("baseline")
        .outstanding_total();

    let mut batch = OtlpLogsReceiver::new()
        .decode(protobuf_with_bodies(&["accept-first", "reject-second"]))
        .expect("decoded batch");
    let decoded_bytes = batch.decoded_bytes.max(1);
    let request_claim = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::new([decoded_bytes, 1, 1, 0, 2, 0, 0, 0, 1, 1, 0]),
    )
    .expect("request claim");
    batch.capacity = Some(
        fixture
            .authority
            .governor()
            .reserve(request_claim)
            .expect("request retained capacity"),
    );
    let mut groups = batch
        .into_admission_groups(&TwoShardPlan)
        .expect("two groups");
    let first = groups.next().expect("first group");
    let second = groups.next().expect("second group");
    assert_eq!(first.shard().value(), 1);
    assert_eq!(second.shard(), second_shard);

    let group_amounts =
        ResourceAmounts::new([1_048_576, 1, 1, 1_048_576, 1, 0, 1, 1, 1, 4, 1_048_576]);
    let group_claim =
        WorkClaim::tenant(fixture.tenant, WorkKind::Ingest, group_amounts).expect("group claim");
    let mut held = Vec::new();
    while let Ok(reservation) = fixture.authority.governor().reserve(group_claim) {
        held.push(reservation);
    }
    assert!(!held.is_empty());

    let policy = IngestPolicy::reject_exact_text_body(1, "second-group-policy", "reject-second")
        .expect("policy");
    let outcome = LogIngest::new(
        &fixture.authority,
        &ledger,
        &policy,
        fixture.tenant,
        second_shard,
        crate::tests::support::schema_session(&fixture).expect("schema"),
    )
    .accept(
        second.into_batch(),
        StoreBlockIdentity::new([0x36; 16]).expect("identity"),
    );
    assert_eq!(
        outcome,
        IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)
    );
    assert!(ledger.snapshot().expect("snapshot").blocks().is_empty());

    drop(held);
    drop(first);
    drop(groups);
    assert_eq!(
        fixture
            .authority
            .governor()
            .inspect()
            .expect("released")
            .outstanding_total(),
        baseline
    );
}
