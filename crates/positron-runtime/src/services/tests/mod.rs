use positron_ingest::{AdmissionGroupPlanFailure, ReceiveFailure};

use super::{ServiceFailure, map_admission_group_plan_failure, map_receive_failure};

mod schema_maintenance;
mod schema_replay_integrity;
mod schema_routes;

#[test]
fn service_diagnostics_are_stable_and_secret_free() {
    assert_eq!(
        ServiceFailure::Unauthorized.to_string(),
        "runtime service request failed"
    );
}

#[test]
fn receiver_failures_preserve_auth_capacity_and_request_classes() {
    assert_eq!(
        map_receive_failure(ReceiveFailure::AuthenticationRejected),
        ServiceFailure::Unauthorized
    );
    assert_eq!(
        map_receive_failure(ReceiveFailure::CapacityUnavailable),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        map_receive_failure(ReceiveFailure::TransportLimitExceeded),
        ServiceFailure::RequestTooLarge
    );
    for failure in [
        ReceiveFailure::MalformedPayload,
        ReceiveFailure::MalformedCompression,
        ReceiveFailure::ValueLimitExceeded,
        ReceiveFailure::TimestampOutOfRange,
        ReceiveFailure::UnsupportedValue,
    ] {
        assert_eq!(map_receive_failure(failure), ServiceFailure::InvalidRequest);
    }
}

#[test]
fn planner_failures_preserve_permanent_retryable_and_invariant_classes() {
    assert_eq!(
        map_admission_group_plan_failure(AdmissionGroupPlanFailure::UnsupportedSignal),
        ServiceFailure::InvalidRequest
    );
    assert_eq!(
        map_admission_group_plan_failure(AdmissionGroupPlanFailure::AssignmentUnavailable),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        map_admission_group_plan_failure(AdmissionGroupPlanFailure::RecordCountExceeded),
        ServiceFailure::Internal
    );
}

#[test]
fn cancellation_is_not_reclassified_as_a_storage_failure() {
    assert_eq!(
        ServiceFailure::Cancelled.bootstrap_code(),
        crate::BootstrapFailureCode::ResourceUnavailable
    );
}

#[test]
fn replay_failures_preserve_resource_integrity_and_cancellation_classes() {
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::StateUnavailable
        ),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::ReplayLimitExceeded
        ),
        ServiceFailure::CapacityUnavailable
    );
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::Schema(
                positron_signals::SchemaFailure::MalformedCatalog,
            )
        ),
        ServiceFailure::CorruptState
    );
    assert_eq!(
        super::schema_bootstrap::classify_replay_failure(
            positron_ingest::SchemaSessionFailure::Cancelled
        ),
        ServiceFailure::Cancelled
    );
}
