use std::net::TcpStream;

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsPartialSuccess, ExportLogsServiceResponse,
};
use positron_governance::CompatibilityHints;
use positron_ingest::{IngestFailureCode, IngestOutcome, OtlpLogsRequestEncoding};
use prost::Message;

use super::native_http::{RequestHead, Response, read_body};
use crate::{ServiceFailure, ServiceHandle};

const INVALID_ARGUMENT: i32 = 3;
const RESOURCE_EXHAUSTED: i32 = 8;
const INTERNAL: i32 = 13;
const UNAVAILABLE: i32 = 14;
const UNAUTHENTICATED: i32 = 16;

#[cfg(test)]
#[path = "otlp_http/tests/mod.rs"]
mod tests;

#[derive(Clone, PartialEq, Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
}

#[derive(Clone, Copy)]
enum ResponseEncoding {
    Json,
    Protobuf,
}

#[cfg(test)]
impl ResponseEncoding {
    const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Protobuf => "application/x-protobuf",
        }
    }
}

pub(super) fn receive(
    stream: &mut TcpStream,
    head: RequestHead,
    services: &ServiceHandle,
) -> Result<Response, Response> {
    let (request_encoding, response_encoding) = request_encoding(
        head.content_type.as_deref(),
        head.content_encoding.as_deref(),
    )?;
    let bearer = head.bearer.ok_or_else(|| {
        failure(
            401,
            UNAUTHENTICATED,
            "OTLP Logs request authentication was rejected",
            response_encoding,
        )
    })?;
    let hints = head
        .tenant_hint
        .as_deref()
        .map(CompatibilityHints::external_tenant_alias)
        .transpose()
        .map_err(|_| {
            failure(
                401,
                UNAUTHENTICATED,
                "OTLP Logs request authentication was rejected",
                response_encoding,
            )
        })?
        .unwrap_or_else(CompatibilityHints::none);
    let context = services
        .authorize_logs_with_hints(&bearer, hints)
        .map_err(|_| {
            failure(
                401,
                UNAUTHENTICATED,
                "OTLP Logs request authentication was rejected",
                response_encoding,
            )
        })?;
    let admission = services
        .admit_logs(context)
        .map_err(|failure| service_response_with_encoding(failure, response_encoding))?;
    let (encoded_limit, decoded_limit) = services
        .logs_transport_limits()
        .map_err(|failure| service_response_with_encoding(failure, response_encoding))?;
    let body_limit = match request_encoding {
        OtlpLogsRequestEncoding::Protobuf | OtlpLogsRequestEncoding::Json => {
            encoded_limit.min(decoded_limit)
        },
        OtlpLogsRequestEncoding::GzipProtobuf | OtlpLogsRequestEncoding::GzipJson => encoded_limit,
    };
    if head.content_length > body_limit {
        return Err(failure(
            413,
            RESOURCE_EXHAUSTED,
            "OTLP Logs request exceeds the receiver limit",
            response_encoding,
        ));
    }
    let body = read_body(stream, head.content_length, body_limit).map_err(|_| {
        failure(
            400,
            INVALID_ARGUMENT,
            "OTLP Logs request body could not be read",
            response_encoding,
        )
    })?;
    let reservation = admission
        .take()
        .map_err(|failure| service_response_with_encoding(failure, response_encoding))?;
    let result = services.ingest_encoded_otlp_logs(context, request_encoding, body, reservation);
    Ok(ingest_response(result, response_encoding))
}

fn request_encoding(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> Result<(OtlpLogsRequestEncoding, ResponseEncoding), Response> {
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    match media_type {
        Some(value) if value.eq_ignore_ascii_case("application/x-protobuf") => {
            let request = compression_variant(
                content_encoding,
                OtlpLogsRequestEncoding::Protobuf,
                OtlpLogsRequestEncoding::GzipProtobuf,
                ResponseEncoding::Protobuf,
            )?;
            Ok((request, ResponseEncoding::Protobuf))
        },
        Some(value) if value.eq_ignore_ascii_case("application/json") => {
            let request = compression_variant(
                content_encoding,
                OtlpLogsRequestEncoding::Json,
                OtlpLogsRequestEncoding::GzipJson,
                ResponseEncoding::Json,
            )?;
            Ok((request, ResponseEncoding::Json))
        },
        _ => Err(failure(
            415,
            INVALID_ARGUMENT,
            "OTLP Logs Content-Type is unsupported",
            ResponseEncoding::Json,
        )),
    }
}

fn compression_variant(
    content_encoding: Option<&str>,
    plain: OtlpLogsRequestEncoding,
    gzip: OtlpLogsRequestEncoding,
    response_encoding: ResponseEncoding,
) -> Result<OtlpLogsRequestEncoding, Response> {
    match content_encoding.map(str::trim) {
        None | Some("") => Ok(plain),
        Some(value) if value.eq_ignore_ascii_case("gzip") => Ok(gzip),
        Some(value) if value.eq_ignore_ascii_case("identity") => Ok(plain),
        Some(_) => Err(failure(
            415,
            INVALID_ARGUMENT,
            "OTLP Logs Content-Encoding is unsupported",
            response_encoding,
        )),
    }
}

fn ingest_response(
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
        Err(failure_code) => service_response_with_encoding(failure_code, encoding),
    }
}

fn success(rejected: usize, encoding: ResponseEncoding) -> Response {
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

fn service_response_with_encoding(
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
        ServiceFailure::KeyUnavailable | ServiceFailure::StorageUnavailable => failure(
            503,
            UNAVAILABLE,
            "OTLP Logs ingest is temporarily unavailable",
            encoding,
        ),
        ServiceFailure::Internal => failure(500, INTERNAL, "OTLP Logs ingest failed", encoding),
    }
}

fn failure(status: u16, code: i32, message: &str, encoding: ResponseEncoding) -> Response {
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
