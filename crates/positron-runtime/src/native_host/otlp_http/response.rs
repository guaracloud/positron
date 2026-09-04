use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceResponse,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceResponse,
};
use prost::Message;

use super::super::native_http::Response;
use super::super::otlp_outcome::{OtlpFailure, OtlpSignal};
use super::{INTERNAL, ResponseEncoding};
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
    response_for_signal(result, encoding, OtlpSignal::Logs)
}

pub(crate) fn ingest_trace_response(
    result: Result<positron_ingest::IngestRequestOutcome, ServiceFailure>,
    encoding: ResponseEncoding,
) -> Response {
    response_for_signal(result, encoding, OtlpSignal::Traces)
}

fn response_for_signal(
    result: Result<positron_ingest::IngestRequestOutcome, ServiceFailure>,
    encoding: ResponseEncoding,
    signal: OtlpSignal,
) -> Response {
    match result {
        Ok(outcome) => match outcome.terminal_failure() {
            Some(outcome) => failure_response(signal.outcome_failure(outcome), encoding),
            None => match signal {
                OtlpSignal::Logs => success(outcome.permanently_rejected_records(), encoding),
                OtlpSignal::Traces => {
                    trace_success(outcome.permanently_rejected_records(), encoding)
                },
            },
        },
        Err(service_failure) => service_response_for_signal(service_failure, encoding, signal),
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

fn failure_response(classification: OtlpFailure, encoding: ResponseEncoding) -> Response {
    let response = failure(
        classification.http_status,
        classification.grpc_code,
        classification.message,
        encoding,
    );
    if classification.retry_after {
        response.with_retry_after(1)
    } else {
        response
    }
}

pub(crate) fn service_response_with_encoding(
    service_failure: ServiceFailure,
    encoding: ResponseEncoding,
) -> Response {
    service_response_for_signal(service_failure, encoding, OtlpSignal::Logs)
}

pub(crate) fn trace_service_response_with_encoding(
    service_failure: ServiceFailure,
    encoding: ResponseEncoding,
) -> Response {
    service_response_for_signal(service_failure, encoding, OtlpSignal::Traces)
}

fn service_response_for_signal(
    service_failure: ServiceFailure,
    encoding: ResponseEncoding,
    signal: OtlpSignal,
) -> Response {
    failure_response(signal.service_failure(service_failure), encoding)
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
