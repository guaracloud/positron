use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceResponse,
};
use positron_ingest::{IngestFailureCode, IngestOutcome};
use prost::Message;

use super::super::native_http::Response;
use super::{
    INTERNAL, INVALID_ARGUMENT, RESOURCE_EXHAUSTED, ResponseEncoding, UNAUTHENTICATED, UNAVAILABLE,
};
use crate::ServiceFailure;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct RpcStatus {
    #[prost(int32, tag = "1")]
    pub(crate) code: i32,
    #[prost(string, tag = "2")]
    pub(crate) message: String,
}

pub(crate) fn ingest_response(
    result: Result<positron_ingest::IngestRequestOutcome, ServiceFailure>,
    encoding: ResponseEncoding,
) -> Response {
    match result {
        Ok(outcome) => match outcome.terminal_failure() {
            Some(IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)) => failure(
                429,
                RESOURCE_EXHAUSTED,
                "OTLP Logs ingest capacity is unavailable",
                encoding,
            )
            .with_retry_after(1),
            Some(IngestOutcome::Retryable(_)) => failure(
                503,
                UNAVAILABLE,
                "OTLP Logs ingest is temporarily unavailable",
                encoding,
            ),
            Some(IngestOutcome::Permanent(_)) => failure(
                400,
                INVALID_ARGUMENT,
                "OTLP Logs request was rejected",
                encoding,
            ),
            Some(IngestOutcome::Ambiguous(_)) => failure(
                503,
                UNAVAILABLE,
                "OTLP Logs commit outcome is ambiguous; retry may duplicate records",
                encoding,
            ),
            Some(IngestOutcome::Full(_) | IngestOutcome::Partial(_)) => failure(
                500,
                INTERNAL,
                "OTLP Logs outcome aggregation failed",
                encoding,
            ),
            None => success(outcome.permanently_rejected_records(), encoding),
        },
        Err(failure_code) => {
            super::response::service_response_with_encoding(failure_code, encoding)
        },
    }
}

pub(crate) fn ingest_trace_response(
    result: Result<positron_ingest::IngestRequestOutcome, ServiceFailure>,
    encoding: ResponseEncoding,
) -> Response {
    match result {
        Ok(outcome) => match outcome.terminal_failure() {
            Some(IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)) => failure(
                429,
                RESOURCE_EXHAUSTED,
                "OTLP Traces ingest capacity is unavailable",
                encoding,
            )
            .with_retry_after(1),
            Some(IngestOutcome::Retryable(_)) => failure(
                503,
                UNAVAILABLE,
                "OTLP Traces ingest is temporarily unavailable",
                encoding,
            ),
            Some(IngestOutcome::Permanent(_)) => failure(
                400,
                INVALID_ARGUMENT,
                "OTLP Traces request was rejected",
                encoding,
            ),
            Some(IngestOutcome::Ambiguous(_)) => failure(
                503,
                UNAVAILABLE,
                "OTLP Traces commit outcome is ambiguous; retry may duplicate spans",
                encoding,
            ),
            Some(IngestOutcome::Full(_) | IngestOutcome::Partial(_)) => failure(
                500,
                INTERNAL,
                "OTLP Traces outcome aggregation failed",
                encoding,
            ),
            None => trace_success(outcome.permanently_rejected_records(), encoding),
        },
        Err(failure_code) => {
            super::response::trace_service_response_with_encoding(failure_code, encoding)
        },
    }
}

pub(crate) fn success(rejected: usize, encoding: ResponseEncoding) -> Response {
    let partial_success = if rejected == 0 {
        None
    } else {
        let Ok(rejected_log_records) = i64::try_from(rejected) else {
            return failure(
                500,
                INTERNAL,
                "OTLP Logs outcome could not be represented",
                encoding,
            );
        };
        Some(ExportLogsPartialSuccess {
            rejected_log_records,
            error_message: "some log records were permanently rejected".to_owned(),
        })
    };
    match encoding {
        ResponseEncoding::Protobuf => Response::protobuf(
            200,
            ExportLogsServiceResponse { partial_success }.encode_to_vec(),
        ),
        ResponseEncoding::Json => match partial_success {
            None => Response::json(200, "{}".to_owned()),
            Some(partial) => match serde_json::to_string(&partial.error_message) {
                Ok(message) => Response::json(
                    200,
                    format!(
                        "{{\"partialSuccess\":{{\"rejectedLogRecords\":\"{}\",\"errorMessage\":{message}}}}}",
                        partial.rejected_log_records,
                    ),
                ),
                Err(_) => failure(
                    500,
                    INTERNAL,
                    "OTLP Logs response encoding failed",
                    encoding,
                ),
            },
        },
    }
}

pub(crate) fn trace_success(rejected: usize, encoding: ResponseEncoding) -> Response {
    let partial_success = if rejected == 0 {
        None
    } else {
        let Ok(rejected_spans) = i64::try_from(rejected) else {
            return failure(
                500,
                INTERNAL,
                "OTLP Traces outcome could not be represented",
                encoding,
            );
        };
        Some(ExportTracePartialSuccess {
            rejected_spans,
            error_message: "some spans were permanently rejected".to_owned(),
        })
    };
    match encoding {
        ResponseEncoding::Protobuf => Response::protobuf(
            200,
            ExportTraceServiceResponse { partial_success }.encode_to_vec(),
        ),
        ResponseEncoding::Json => match partial_success {
            None => Response::json(200, "{}".to_owned()),
            Some(partial) => match serde_json::to_string(&partial.error_message) {
                Ok(message) => Response::json(
                    200,
                    format!(
                        "{{\"partialSuccess\":{{\"rejectedSpans\":\"{}\",\"errorMessage\":{message}}}}}",
                        partial.rejected_spans,
                    ),
                ),
                Err(_) => failure(
                    500,
                    INTERNAL,
                    "OTLP Traces response encoding failed",
                    encoding,
                ),
            },
        },
    }
}

pub(crate) fn service_response_with_encoding(
    service_failure: ServiceFailure,
    encoding: ResponseEncoding,
) -> Response {
    match service_failure {
        ServiceFailure::Unauthorized => failure(
            401,
            UNAUTHENTICATED,
            "OTLP Logs request authentication was rejected",
            encoding,
        ),
        ServiceFailure::CapacityUnavailable => failure(
            429,
            RESOURCE_EXHAUSTED,
            "OTLP Logs ingest capacity is unavailable",
            encoding,
        )
        .with_retry_after(1),
        ServiceFailure::RequestTooLarge => failure(
            413,
            RESOURCE_EXHAUSTED,
            "OTLP Logs request exceeds the receiver limit",
            encoding,
        ),
        ServiceFailure::InvalidRequest => failure(
            400,
            INVALID_ARGUMENT,
            "OTLP Logs request was rejected",
            encoding,
        ),
        ServiceFailure::KeyUnavailable
        | ServiceFailure::CatalogUnavailable
        | ServiceFailure::LedgerUnavailable
        | ServiceFailure::StorageUnavailable => failure(
            503,
            UNAVAILABLE,
            "OTLP Logs ingest is temporarily unavailable",
            encoding,
        ),
        ServiceFailure::CorruptState | ServiceFailure::Internal | ServiceFailure::Cancelled => {
            failure(500, INTERNAL, "OTLP Logs ingest failed", encoding)
        },
    }
}

pub(crate) fn trace_service_response_with_encoding(
    service_failure: ServiceFailure,
    encoding: ResponseEncoding,
) -> Response {
    match service_failure {
        ServiceFailure::Unauthorized => failure(
            401,
            UNAUTHENTICATED,
            "OTLP Traces request authentication was rejected",
            encoding,
        ),
        ServiceFailure::CapacityUnavailable => failure(
            429,
            RESOURCE_EXHAUSTED,
            "OTLP Traces ingest capacity is unavailable",
            encoding,
        )
        .with_retry_after(1),
        ServiceFailure::RequestTooLarge => failure(
            413,
            RESOURCE_EXHAUSTED,
            "OTLP Traces request exceeds the receiver limit",
            encoding,
        ),
        ServiceFailure::InvalidRequest => failure(
            400,
            INVALID_ARGUMENT,
            "OTLP Traces request was rejected",
            encoding,
        ),
        ServiceFailure::KeyUnavailable
        | ServiceFailure::CatalogUnavailable
        | ServiceFailure::LedgerUnavailable
        | ServiceFailure::StorageUnavailable => failure(
            503,
            UNAVAILABLE,
            "OTLP Traces ingest is temporarily unavailable",
            encoding,
        ),
        ServiceFailure::CorruptState | ServiceFailure::Internal | ServiceFailure::Cancelled => {
            failure(500, INTERNAL, "OTLP Traces ingest failed", encoding)
        },
    }
}

pub(crate) fn failure(
    status: u16,
    code: i32,
    message: &str,
    encoding: ResponseEncoding,
) -> Response {
    match encoding {
        ResponseEncoding::Json => match serde_json::to_string(message) {
            Ok(message) => {
                Response::json(status, format!("{{\"code\":{code},\"message\":{message}}}"))
            },
            Err(_) => Response::empty(500),
        },
        ResponseEncoding::Protobuf => Response::protobuf(
            status,
            RpcStatus {
                code,
                message: message.to_owned(),
            }
            .encode_to_vec(),
        ),
    }
}
