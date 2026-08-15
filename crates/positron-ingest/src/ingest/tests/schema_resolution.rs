use crate::TenantSchemaRegistry;
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
    LogRecord, LogStore, SchemaBudget, SchemaCatalog, SchemaDelta, SchemaMutationPermit,
    TenantSchemaState,
};

use super::{
    IngestFailureCode, IngestOutcome, SchemaSessionFailure, map_schema_session_failure,
    rollback_schema,
};

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
        StoreBlockIdentity::new([0x62; 16]).expect("identity"),
        VirtualShardId::new(1).expect("shard"),
        staged_delta(&fixture),
        9_000_000,
        [0x63; 32],
        failure,
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
    let permit = SchemaMutationPermit::for_new_catalog(&capacity, tenant, budget).expect("permit");
    TenantSchemaState::new(&permit, tenant, budget)
        .expect("catalog")
        .stage_group(&permit, &mut records)
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
