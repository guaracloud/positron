use positron_ingest::{IngestFailureCode, IngestOutcome};

use super::{
    ResponseEncoding, decode_status, decode_success, decode_trace_success, ingest_response, single,
    success, trace_service_response_with_encoding, trace_success,
};
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
            (
                ServiceFailure::Cancelled,
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

#[test]
fn trace_success_and_partial_success_have_canonical_shapes_in_both_encodings() {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let full = trace_success(0, encoding);
        assert_eq!(full.status(), 200);
        assert!(
            decode_trace_success(&full, encoding)
                .partial_success
                .is_none()
        );

        let partial = trace_success(2, encoding);
        assert_eq!(partial.status(), 200);
        let partial = decode_trace_success(&partial, encoding)
            .partial_success
            .expect("partial success");
        assert_eq!(partial.rejected_spans, 2);
        assert_eq!(
            partial.error_message,
            "some spans were permanently rejected"
        );
    }
    assert_eq!(
        trace_success(2, ResponseEncoding::Json).body(),
        br#"{"partialSuccess":{"rejectedSpans":"2","errorMessage":"some spans were permanently rejected"}}"#,
    );
}

#[test]
fn trace_service_failures_keep_http_retry_classes_and_messages() {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        let capacity =
            trace_service_response_with_encoding(ServiceFailure::CapacityUnavailable, encoding);
        assert_eq!(capacity.status(), 429);
        assert_eq!(decode_status(&capacity, encoding).code, 8);
        assert_eq!(capacity.retry_after_seconds(), Some(1));

        let malformed =
            trace_service_response_with_encoding(ServiceFailure::InvalidRequest, encoding);
        assert_eq!(malformed.status(), 400);
        assert_eq!(decode_status(&malformed, encoding).code, 3);
        assert_eq!(
            decode_status(&malformed, encoding).message,
            "OTLP Traces request was rejected"
        );
    }
}

#[test]
fn trace_retry_permanent_and_ambiguous_outcomes_keep_their_public_classes() {
    for encoding in [ResponseEncoding::Protobuf, ResponseEncoding::Json] {
        for (outcome, status, code, message, retry_after) in [
            (
                IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable),
                429,
                8,
                "OTLP Traces ingest capacity is unavailable",
                Some(1),
            ),
            (
                IngestOutcome::Retryable(IngestFailureCode::StorageUnavailable),
                503,
                14,
                "OTLP Traces ingest is temporarily unavailable",
                None,
            ),
            (
                IngestOutcome::Permanent(IngestFailureCode::PolicyRejected),
                400,
                3,
                "OTLP Traces request was rejected",
                None,
            ),
            (
                IngestOutcome::Permanent(IngestFailureCode::ValueLimitExceeded),
                400,
                3,
                "OTLP Traces request was rejected",
                None,
            ),
            (
                IngestOutcome::Ambiguous(IngestFailureCode::StorageUnavailable),
                503,
                14,
                "OTLP Traces commit outcome is ambiguous; retry may duplicate spans",
                None,
            ),
        ] {
            let response = super::super::ingest_trace_response(Ok(single(outcome)), encoding);
            assert_eq!(response.status(), status);
            assert_eq!(response.content_type(), encoding.content_type());
            let rendered = decode_status(&response, encoding);
            assert_eq!(rendered.code, code);
            assert_eq!(rendered.message, message);
            assert_eq!(response.retry_after_seconds(), retry_after);
        }
    }
}
