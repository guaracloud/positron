use crate::TenantSchemaRegistry;
use crate::schema_session::SchemaBuildObserver;
use positron_domain::routing::VirtualShardId;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::StoreBlockIdentity;
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::SchemaFailure;
use positron_signals::{
    LogRecord, LogStore, SchemaBudget, SchemaCatalog, SchemaDelta, SchemaSessionStore,
};

use super::super::schema_admission_estimate;
use super::{
    IngestFailureCode, IngestOutcome, SchemaSessionFailure, map_schema_session_failure,
    rollback_schema,
};

#[test]
fn production_observed_schema_stage_publishes_a_complete_text_summary() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string(
            "prefix needle suffix".to_owned(),
        )),
        Vec::new(),
        LogMetadata::empty(),
    );
    let estimate = schema_admission_estimate(std::slice::from_ref(&candidate))
        .expect("bounded schema estimate");
    assert!(estimate.text_work_units() > 0);
    let policy = IngestPolicy::preserving(1).expect("policy");
    let PolicyEvaluation::Accepted(evaluated) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("preserving policy rejected fixture");
    };
    let mut records = vec![
        LogRecord::checked_evaluated(LogStore::value_limit_profile(), *evaluated).expect("record"),
    ];
    let budget = SchemaBudget::release_1().expect("budget");
    let memory = u64::try_from(SchemaCatalog::base_memory_bound(budget).expect("bound"))
        .expect("bounded memory");
    let reservation = fixture
        .authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                fixture.tenant,
                WorkKind::Ingest,
                ResourceAmounts::new([
                    memory,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    estimate.schema_work_units(),
                    0,
                    0,
                ]),
            )
            .expect("claim"),
        )
        .expect("reservation");
    let session =
        SchemaSessionStore::new(reservation, fixture.tenant, budget).expect("schema session");
    let observer = SchemaBuildObserver::new(estimate.schema_work_units(), None);
    let delta = session
        .stage_group_observed(&mut records, &observer)
        .expect("observed schema stage");
    assert!(delta.staged_memory_bytes() > 0);
    let consumed = observer.consumed();
    assert!(consumed > 0);
    let mut fallback_records = records.clone();
    let exact_minus_one = SchemaBuildObserver::new(consumed - 1, None);
    let fallback = session
        .stage_group_observed(&mut fallback_records, &exact_minus_one)
        .expect("budget exhaustion falls back to an unindexed stage");
    assert_eq!(fallback.staged_memory_bytes(), 0);
}

#[test]
fn schema_failures_keep_their_closed_ingest_outcomes() {
    let cases = [
        (
            SchemaSessionFailure::TenantConflict,
            IngestOutcome::Permanent(IngestFailureCode::TenantConflict),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::InvalidBudget),
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::InvalidPath),
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::PathTooLong),
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::InvalidValue),
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::MalformedCatalog),
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::LimitExceeded),
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        ),
        (
            SchemaSessionFailure::ReplayLimitExceeded,
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        ),
        (
            SchemaSessionFailure::RegistryLimitExceeded,
            IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
        ),
        (
            SchemaSessionFailure::Schema(SchemaFailure::AllocationUnavailable),
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
        ),
        (
            SchemaSessionFailure::StateUnavailable,
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
        ),
        (
            SchemaSessionFailure::InFlight,
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
        ),
        (
            SchemaSessionFailure::PendingReconciliationRequired,
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
        ),
        (
            SchemaSessionFailure::ReplayIntegrity,
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
        ),
    ];

    for (failure, expected) in cases {
        assert_eq!(map_schema_session_failure(failure), expected);
    }
}

#[test]
fn rollback_refuses_a_delta_without_the_matching_inflight_identity() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let tenant = fixture.tenant;
    let delta = staged_delta(&fixture);
    let session = TenantSchemaRegistry::new(1)
        .expect("registry")
        .session(tenant, fixture.authority.governor())
        .expect("session");

    assert_eq!(
        rollback_schema(
            &session,
            StoreBlockIdentity::new([0x61; 16]).expect("identity"),
            VirtualShardId::new(1).expect("shard"),
            delta,
            IngestOutcome::Permanent(IngestFailureCode::InvalidRecord),
            fixture.authority.governor(),
        ),
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
    );
}

#[test]
fn schema_retention_zero_and_success_paths_release_exactly() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    for (bytes, retained) in [(0, false), (1, true)] {
        let claim = WorkClaim::tenant(
            fixture.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2).expect("amounts"),
        )
        .expect("claim");
        let reservation = fixture
            .authority
            .governor()
            .reserve(claim)
            .expect("reservation");
        let super::super::SchemaCapacityRetention::Retained(capacity) =
            super::super::retain_schema_capacity(reservation, bytes)
        else {
            panic!("bounded retention must succeed");
        };
        assert_eq!(capacity.is_some(), retained);
    }
}

#[test]
fn failed_retention_still_resolves_the_durable_schema_lifecycle() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let claim = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amounts"),
    )
    .expect("claim");
    let reservation = fixture
        .authority
        .governor()
        .reserve(claim)
        .expect("reservation");
    let super::super::SchemaCapacityRetention::Failed(failure) =
        super::super::retain_schema_capacity(reservation, 9_000_000)
    else {
        panic!("growth must fail");
    };
    let session = TenantSchemaRegistry::new(1)
        .expect("registry")
        .session(fixture.tenant, fixture.authority.governor())
        .expect("session");
    let outcome = super::super::resolve_after_retention_failure(
        &session,
        super::super::RetentionResolution {
            identity: StoreBlockIdentity::new([0x62; 16]).expect("identity"),
            shard: VirtualShardId::new(1).expect("shard"),
            staged: staged_delta(&fixture),
            capacity_bytes: 9_000_000,
            digest: [0x63; 32],
        },
        failure,
        fixture.authority.governor(),
    );
    assert_eq!(
        outcome,
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
    );
}

fn staged_delta(fixture: &crate::tests::support::Fixture) -> SchemaDelta {
    let tenant = fixture.tenant;
    let policy = IngestPolicy::preserving(1).expect("policy");
    let candidate = NativeLogCandidate::new(
        None,
        None,
        Some(CandidateAttributeValue::string("body".to_owned())),
        vec![NativeLogAttribute::new(
            AttributeNamespace::Record,
            "schema".to_owned(),
            vec![CandidateAttributeValue::string("value".to_owned())],
        )],
        LogMetadata::empty(),
    );
    let PolicyEvaluation::Accepted(evaluated) = policy
        .evaluate(candidate, PolicyReceiver::OtlpGrpc)
        .expect("evaluation")
    else {
        panic!("preserving policy rejected fixture");
    };
    let mut records = vec![
        LogRecord::checked_evaluated(LogStore::value_limit_profile(), *evaluated).expect("record"),
    ];
    let budget = SchemaBudget::release_1().expect("budget");
    let bytes = u64::try_from(SchemaCatalog::base_memory_bound(budget).expect("bound"))
        .expect("bounded memory");
    let capacity = fixture
        .authority
        .governor()
        .reserve(
            WorkClaim::tenant(
                tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, bytes).expect("amounts"),
            )
            .expect("claim"),
        )
        .expect("capacity");
    SchemaSessionStore::new(capacity, tenant, budget)
        .expect("catalog")
        .stage_group(&mut records)
        .expect("delta")
}

#[test]
fn failed_schema_retention_returns_the_live_reservation_for_durable_resolution() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let claim = WorkClaim::tenant(
        fixture.tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::MemoryBytes, 1).expect("amounts"),
    )
    .expect("claim");
    let reservation = fixture
        .authority
        .governor()
        .reserve(claim)
        .expect("reservation");

    let super::super::SchemaCapacityRetention::Failed(failure) =
        super::super::retain_schema_capacity(reservation, 9_000_000)
    else {
        panic!("growth must be rejected by the tenant quota");
    };
    let (reservation, outcome) = failure.into_parts();
    assert!(reservation.is_active());
    assert_eq!(
        outcome,
        IngestOutcome::Ambiguous(IngestFailureCode::CapacityUnavailable)
    );
}
