use positron_ingest::{IngestFailureCode, IngestOutcome};
use tonic::Code;

use super::{render, service_status};
use crate::ServiceFailure;

#[test]
fn retryable_outcomes_have_stable_public_statuses() {
    let capacity = render(IngestOutcome::Retryable(
        IngestFailureCode::CapacityUnavailable,
    ))
    .expect_err("capacity refusal must remain retryable");
    assert_eq!(capacity.code(), Code::ResourceExhausted);
    assert_eq!(
        capacity.message(),
        "OTLP Logs ingest capacity is unavailable"
    );

    let storage = render(IngestOutcome::Retryable(
        IngestFailureCode::StorageUnavailable,
    ))
    .expect_err("transient storage failure must remain retryable");
    assert_eq!(storage.code(), Code::Unavailable);
    assert_eq!(
        storage.message(),
        "OTLP Logs ingest is temporarily unavailable"
    );
}

#[test]
fn permanent_and_ambiguous_outcomes_cannot_be_confused() {
    let permanent = render(IngestOutcome::Permanent(IngestFailureCode::PolicyRejected))
        .expect_err("permanent rejection must fail the export");
    assert_eq!(permanent.code(), Code::InvalidArgument);
    assert_eq!(permanent.message(), "OTLP Logs request was rejected");

    let ambiguous = render(IngestOutcome::Ambiguous(
        IngestFailureCode::StorageUnavailable,
    ))
    .expect_err("ambiguous commit must require an at-least-once decision");
    assert_eq!(ambiguous.code(), Code::Unavailable);
    assert_eq!(
        ambiguous.message(),
        "OTLP Logs commit outcome is ambiguous; retry may duplicate records"
    );
}

#[test]
fn runtime_service_failures_keep_one_stable_public_taxonomy() {
    for (failure, code, message) in [
        (
            ServiceFailure::Unauthorized,
            Code::Unauthenticated,
            "OTLP Logs request authentication was rejected",
        ),
        (
            ServiceFailure::InvalidRequest,
            Code::InvalidArgument,
            "OTLP Logs request was rejected",
        ),
        (
            ServiceFailure::KeyUnavailable,
            Code::Unavailable,
            "OTLP Logs ingest is temporarily unavailable",
        ),
        (
            ServiceFailure::StorageUnavailable,
            Code::Unavailable,
            "OTLP Logs ingest is temporarily unavailable",
        ),
        (
            ServiceFailure::Internal,
            Code::Internal,
            "OTLP Logs ingest failed",
        ),
    ] {
        let status = service_status(failure);
        assert_eq!(status.code(), code);
        assert_eq!(status.message(), message);
    }
}
