use super::*;

#[test]
fn push_success_retry_permanent_and_ambiguous_outcomes_are_stable() {
    let success = ingest_response(Ok(IngestRequestOutcome::new(Vec::new())));
    assert_eq!(success.status(), 204);
    assert!(success.body().is_empty());

    for (outcome, status, retry_after, message) in [
        (
            IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
            429,
            Some(1),
            "Loki Push ingest capacity is unavailable",
        ),
        (
            IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
            503,
            None,
            "Loki Push ingest is temporarily unavailable",
        ),
        (
            IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
            400,
            None,
            "Loki Push request was rejected",
        ),
        (
            IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable),
            503,
            None,
            "Loki Push commit outcome is ambiguous; retry may duplicate records",
        ),
    ] {
        let response = ingest_response(Ok(single(outcome)));
        assert_eq!(response.status(), status);
        assert_eq!(response.retry_after_seconds(), retry_after);
        let decoded: serde_json::Value =
            serde_json::from_slice(response.body()).expect("valid JSON failure");
        assert_eq!(decoded["status"], "error");
        assert_eq!(decoded["error"], message);
    }
}

#[test]
fn push_service_failures_do_not_claim_durable_success() {
    for (failure, status) in [
        (ServiceFailure::Unauthorized, 401),
        (ServiceFailure::CapacityUnavailable, 429),
        (ServiceFailure::RequestTooLarge, 413),
        (ServiceFailure::InvalidRequest, 400),
        (ServiceFailure::KeyUnavailable, 503),
        (ServiceFailure::StorageUnavailable, 503),
        (ServiceFailure::Internal, 500),
    ] {
        assert_eq!(ingest_response(Err(failure)).status(), status);
    }
}
