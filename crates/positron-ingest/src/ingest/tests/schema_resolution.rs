use positron_domain::identity::TenantId;
use positron_domain::routing::VirtualShardId;
use positron_domain::value::{AttributeNamespace, CandidateAttributeValue};
use positron_kernel::StoreBlockIdentity;
use positron_policy::{
    IngestPolicy, LogMetadata, NativeLogAttribute, NativeLogCandidate, PolicyEvaluation,
    PolicyReceiver,
};
use positron_signals::SchemaFailure;
use positron_signals::{LogRecord, LogStore, SchemaBudget, SchemaCatalog};

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
    let catalog =
        SchemaCatalog::new(tenant, SchemaBudget::release_1().expect("budget")).expect("catalog");
    let delta = LogStore::new()
        .stage_schema_group(&mut records, &catalog)
        .expect("delta");
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
