use positron_ingest::{IngestFailureCode, IngestOutcome};

use super::{ResponseEncoding, decode_status, decode_success, ingest_response, single, success};
use crate::ServiceFailure;

#[test]
fn success_and_partial_success_have_otlp_shapes_in_both_encodings() {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let full = success(0, encoding);
        assert_eq!(full.status(), 200);
        assert!(decode_success(&full, encoding).partial_success.is_none());

        let partial = success(2, encoding);
        assert_eq!(partial.status(), 200);
        let partial = decode_success(&partial, encoding)
            .partial_success
            .expect("partial success");
        assert_eq!(partial.rejected_log_records, 2);
        assert_eq!(
            partial.error_message,
            "some log records were permanently rejected"
        );

        let unrepresentable = success(usize::MAX, encoding);
        assert_eq!(unrepresentable.status(), 500);
        assert_eq!(
            decode_status(&unrepresentable, encoding).message,
            "OTLP Logs outcome could not be represented"
        );
    }
}

#[test]
fn json_success_uses_exact_canonical_protojson() {
    assert_eq!(success(0, ResponseEncoding::Json).body(), b"{}");
    assert_eq!(
        success(2, ResponseEncoding::Json).body(),
        br#"{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"some log records were permanently rejected"}}"#,
    );
}

#[test]
fn service_failures_have_stable_protocol_statuses() {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        for (failure, http_status, rpc_code, message, retry_after) in [
            (
                ServiceFailure::Unauthorized,
                401,
                16,
                "OTLP Logs request authentication was rejected",
                None,
            ),
            (
                ServiceFailure::CapacityUnavailable,
                429,
                8,
                "OTLP Logs ingest capacity is unavailable",
                Some(1),
            ),
            (
                ServiceFailure::RequestTooLarge,
                413,
                8,
                "OTLP Logs request exceeds the receiver limit",
                None,
            ),
            (
                ServiceFailure::InvalidRequest,
                400,
                3,
                "OTLP Logs request was rejected",
                None,
            ),
            (
                ServiceFailure::KeyUnavailable,
                503,
                14,
                "OTLP Logs ingest is temporarily unavailable",
                None,
            ),
            (
                ServiceFailure::StorageUnavailable,
                503,
                14,
                "OTLP Logs ingest is temporarily unavailable",
                None,
            ),
            (
                ServiceFailure::Internal,
                500,
                13,
                "OTLP Logs ingest failed",
                None,
            ),
        ] {
            let response = ingest_response(Err(failure), encoding);
            assert_eq!(response.status(), http_status);
            assert_eq!(response.content_type(), encoding.content_type());
            let status = decode_status(&response, encoding);
            assert_eq!(status.code, rpc_code);
            assert_eq!(status.message, message);
            assert_eq!(response.retry_after_seconds(), retry_after);
        }
    }
}

#[test]
fn json_failure_uses_exact_google_rpc_status_protojson() {
    assert_eq!(
        ingest_response(Err(ServiceFailure::InvalidRequest), ResponseEncoding::Json).body(),
        br#"{"code":3,"message":"OTLP Logs request was rejected"}"#,
    );
}

#[test]
fn retry_permanent_and_ambiguous_outcomes_have_stable_http_statuses() {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        for (outcome, http_status, rpc_code, message) in [
            (
                IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
                429,
                8,
                "OTLP Logs ingest capacity is unavailable",
            ),
            (
                IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
                503,
                14,
                "OTLP Logs ingest is temporarily unavailable",
            ),
            (
                IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
                400,
                3,
                "OTLP Logs request was rejected",
            ),
            (
                IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable),
                503,
                14,
                "OTLP Logs commit outcome is ambiguous; retry may duplicate records",
            ),
        ] {
            let response = ingest_response(Ok(single(outcome)), encoding);
            assert_eq!(response.status(), http_status);
            assert_eq!(response.content_type(), encoding.content_type());
            let status = decode_status(&response, encoding);
            assert_eq!(status.code, rpc_code);
            assert_eq!(status.message, message);
            assert_eq!(
                response.retry_after_seconds(),
                (http_status == 429).then_some(1)
            );
        }
    }
}
