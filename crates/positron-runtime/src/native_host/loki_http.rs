use std::net::TcpStream;

use positron_governance::CompatibilityHints;
use positron_ingest::{IngestFailureCode, IngestOutcome, LokiPushRequestEncoding};

use super::native_http::{RequestHead, Response, read_body};
use crate::{ServiceFailure, ServiceHandle};

#[cfg(test)]
#[path = "loki_http/tests/mod.rs"]
mod tests;

pub(super) fn receive_push(
    stream: &mut TcpStream,
    head: RequestHead,
    services: &ServiceHandle,
) -> Result<Response, Response> {
    let encoding = request_encoding(
        head.content_type.as_deref(),
        head.content_encoding.as_deref(),
    )?;
    let bearer = head
        .bearer
        .ok_or_else(|| failure(401, "Loki Push authentication was rejected"))?;
    let hints = head
        .tenant_hint
        .as_deref()
        .map(CompatibilityHints::external_tenant_alias)
        .transpose()
        .map_err(|_| failure(401, "Loki Push authentication was rejected"))?
        .unwrap_or_else(CompatibilityHints::none);
    let context = services
        .authorize_logs_with_hints(&bearer, hints)
        .map_err(|_| failure(401, "Loki Push authentication was rejected"))?;
    let admission = services.admit_logs(context).map_err(service_response)?;
    let (encoded_limit, decoded_limit) =
        services.logs_transport_limits().map_err(service_response)?;
    let body_limit = match encoding {
        LokiPushRequestEncoding::Json => encoded_limit.min(decoded_limit),
        LokiPushRequestEncoding::GzipJson
        | LokiPushRequestEncoding::DeflateJson
        | LokiPushRequestEncoding::SnappyProtobuf => encoded_limit,
    };
    if head.content_length > body_limit {
        return Err(failure(413, "Loki Push request exceeds the receiver limit"));
    }
    let body = read_body(stream, head.content_length, body_limit)
        .map_err(|_| failure(400, "Loki Push request body could not be read"))?;
    let reservation = admission.take().map_err(service_response)?;
    Ok(ingest_response(services.ingest_encoded_loki_push(
        context,
        encoding,
        body,
        reservation,
    )))
}

fn request_encoding(
    content_type: Option<&str>,
    content_encoding: Option<&str>,
) -> Result<LokiPushRequestEncoding, Response> {
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    match media_type {
        Some(value) if value.eq_ignore_ascii_case("application/json") => {
            match content_encoding.map(str::trim) {
                None | Some("") => Ok(LokiPushRequestEncoding::Json),
                Some(value) if value.eq_ignore_ascii_case("identity") => {
                    Ok(LokiPushRequestEncoding::Json)
                },
                Some(value) if value.eq_ignore_ascii_case("gzip") => {
                    Ok(LokiPushRequestEncoding::GzipJson)
                },
                Some(value) if value.eq_ignore_ascii_case("deflate") => {
                    Ok(LokiPushRequestEncoding::DeflateJson)
                },
                Some(_) => Err(failure(415, "Loki Push Content-Encoding is unsupported")),
            }
        },
        Some(value) if value.eq_ignore_ascii_case("application/x-protobuf") => {
            match content_encoding.map(str::trim) {
                None | Some("") => Ok(LokiPushRequestEncoding::SnappyProtobuf),
                Some(value) if value.eq_ignore_ascii_case("snappy") => {
                    Ok(LokiPushRequestEncoding::SnappyProtobuf)
                },
                Some(_) => Err(failure(415, "Loki Push Content-Encoding is unsupported")),
            }
        },
        _ => Err(failure(415, "Loki Push Content-Type is unsupported")),
    }
}

fn ingest_response(
    result: Result<positron_ingest::IngestRequestOutcome, ServiceFailure>,
) -> Response {
    match result {
        Ok(outcome) => match outcome.terminal_failure() {
            Some(IngestOutcome::Retryable(IngestFailureCode::CapacityUnavailable)) => {
                failure(429, "Loki Push ingest capacity is unavailable").with_retry_after(1)
            },
            Some(IngestOutcome::Retryable(_)) => {
                failure(503, "Loki Push ingest is temporarily unavailable")
            },
            Some(IngestOutcome::Ambiguous(_)) => failure(
                503,
                "Loki Push commit outcome is ambiguous; retry may duplicate records",
            ),
            Some(IngestOutcome::Permanent(_)) => failure(400, "Loki Push request was rejected"),
            Some(IngestOutcome::Full(_) | IngestOutcome::Partial(_)) => {
                failure(500, "Loki Push outcome aggregation failed")
            },
            None if outcome.permanently_rejected_records() > 0 => {
                failure(400, "Loki Push request was partially rejected")
            },
            None => Response::empty(204),
        },
        Err(service_failure) => service_response(service_failure),
    }
}

fn service_response(service_failure: ServiceFailure) -> Response {
    match service_failure {
        ServiceFailure::Unauthorized => failure(401, "Loki Push authentication was rejected"),
        ServiceFailure::CapacityUnavailable => {
            failure(429, "Loki Push ingest capacity is unavailable").with_retry_after(1)
        },
        ServiceFailure::RequestTooLarge => {
            failure(413, "Loki Push request exceeds the receiver limit")
        },
        ServiceFailure::InvalidRequest => failure(400, "Loki Push request was rejected"),
        ServiceFailure::KeyUnavailable | ServiceFailure::StorageUnavailable => {
            failure(503, "Loki Push ingest is temporarily unavailable")
        },
        ServiceFailure::Internal => failure(500, "Loki Push ingest failed"),
    }
}

fn failure(status: u16, message: &str) -> Response {
    match serde_json::to_string(message) {
        Ok(message) => Response::json(
            status,
            format!("{{\"status\":\"error\",\"error\":{message}}}"),
        ),
        Err(_) => Response::empty(500),
    }
}
