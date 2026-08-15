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
