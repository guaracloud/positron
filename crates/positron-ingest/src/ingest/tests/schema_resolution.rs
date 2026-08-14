use positron_domain::identity::TenantId;
use positron_domain::routing::VirtualShardId;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::StoreBlockIdentity;
use positron_kernel::{ResourceAmounts, ResourceDimension, WorkClaim, WorkKind};
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::SchemaFailure;
use positron_signals::{LogRecord, LogStore, SchemaBudget, SchemaDelta, TenantSchemaState};

use super::{
    IngestFailureCode, IngestOutcome, SchemaSessionFailure, TenantSchemaSession,
    map_schema_session_failure, rollback_schema,
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
    let tenant = TenantId::from_bytes([0x41; 16]).expect("tenant");
    let delta = staged_delta(tenant);
    let session = TenantSchemaSession::release_1(tenant).expect("session");

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
    let session = TenantSchemaSession::release_1(fixture.tenant).expect("session");
    let outcome = super::super::resolve_after_retention_failure(
        &session,
        StoreBlockIdentity::new([0x62; 16]).expect("identity"),
        VirtualShardId::new(1).expect("shard"),
        staged_delta(fixture.tenant),
        9_000_000,
        [0x63; 32],
        failure,
    );
    assert_eq!(
        outcome,
        IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable)
    );
}

fn staged_delta(tenant: TenantId) -> SchemaDelta {
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
    TenantSchemaState::new(tenant, SchemaBudget::release_1().expect("budget"))
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
