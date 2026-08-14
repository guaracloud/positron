use positron_domain::routing::VirtualShardId;
use positron_ingest::{
    AdmissionGroupOutcome, IngestFailureCode, IngestOutcome, IngestRequestOutcome,
};
use tonic::Code;

use super::{map_decode_failure, render, service_status};
use crate::ServiceFailure;

#[test]
fn retryable_outcomes_have_stable_public_statuses() {
    let capacity = render(single(IngestOutcome::Retryable(
        IngestFailureCode::CapacityUnavailable,
    )))
    .expect_err("capacity refusal must remain retryable");
    assert_eq!(capacity.code(), Code::ResourceExhausted);
    assert_eq!(
        capacity.message(),
        "OTLP Logs ingest capacity is unavailable"
    );

    let storage = render(single(IngestOutcome::Retryable(
        IngestFailureCode::StorageUnavailable,
    )))
    .expect_err("transient storage failure must remain retryable");
    assert_eq!(storage.code(), Code::Unavailable);
    assert_eq!(
        storage.message(),
        "OTLP Logs ingest is temporarily unavailable"
    );
}

#[test]
fn permanent_and_ambiguous_outcomes_cannot_be_confused() {
    let permanent = render(single(IngestOutcome::Permanent(
        IngestFailureCode::PolicyRejected,
    )))
    .expect_err("permanent rejection must fail the export");
    assert_eq!(permanent.code(), Code::InvalidArgument);
    assert_eq!(permanent.message(), "OTLP Logs request was rejected");

    let ambiguous = render(single(IngestOutcome::Ambiguous(
        IngestFailureCode::StorageUnavailable,
    )))
    .expect_err("ambiguous commit must require an at-least-once decision");
    assert_eq!(ambiguous.code(), Code::Unavailable);
    assert_eq!(
        ambiguous.message(),
        "OTLP Logs commit outcome is ambiguous; retry may duplicate records"
    );
}

fn single(outcome: IngestOutcome) -> IngestRequestOutcome {
    IngestRequestOutcome::new(vec![AdmissionGroupOutcome::new(
        VirtualShardId::new(1).expect("fixed shard"),
        1,
        outcome,
    )])
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
            ServiceFailure::CapacityUnavailable,
            Code::ResourceExhausted,
            "OTLP Logs ingest capacity is unavailable",
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

#[test]
fn protobuf_wire_decode_failure_is_narrowly_mapped_to_invalid_argument() {
    let mut decode = http::Response::new(());
    decode
        .headers_mut()
        .insert("grpc-status", http::HeaderValue::from_static("13"));
    decode.headers_mut().insert(
        "grpc-message",
        http::HeaderValue::from_static(
            "failed%20to%20decode%20Protobuf%20message:%20private-parser-detail",
        ),
    );
    let decode = map_decode_failure(decode);
    assert_eq!(
        decode.headers().get("grpc-status"),
        Some(&http::HeaderValue::from_static("3"))
    );
    assert_eq!(
        decode.headers().get("grpc-message"),
        Some(&http::HeaderValue::from_static(
            "OTLP%20Logs%20request%20was%20malformed"
        ))
    );

    let mut unrelated = http::Response::new(());
    unrelated
        .headers_mut()
        .insert("grpc-status", http::HeaderValue::from_static("13"));
    unrelated.headers_mut().insert(
        "grpc-message",
        http::HeaderValue::from_static("unrelated%20internal%20failure"),
    );
    assert_eq!(
        map_decode_failure(unrelated).headers().get("grpc-status"),
        Some(&http::HeaderValue::from_static("13"))
    );
}
