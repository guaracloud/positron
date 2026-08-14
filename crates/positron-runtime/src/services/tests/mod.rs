use positron_ingest::ReceiveFailure;

use super::{ServiceFailure, map_receive_failure};

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
    for failure in [
        ReceiveFailure::MalformedPayload,
        ReceiveFailure::MalformedCompression,
        ReceiveFailure::TransportLimitExceeded,
        ReceiveFailure::ValueLimitExceeded,
        ReceiveFailure::TimestampOutOfRange,
        ReceiveFailure::UnsupportedValue,
    ] {
        assert_eq!(map_receive_failure(failure), ServiceFailure::InvalidRequest);
    }
}
