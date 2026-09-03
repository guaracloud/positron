use std::net::TcpStream;

use positron_governance::CompatibilityHints;
use positron_ingest::{OtlpLogsRequestEncoding, OtlpTracesRequestEncoding};

use super::native_http::{RequestHead, Response, read_body};
use crate::ServiceHandle;

const INVALID_ARGUMENT: i32 = 3;
const RESOURCE_EXHAUSTED: i32 = 8;
const INTERNAL: i32 = 13;
const UNAVAILABLE: i32 = 14;
const UNAUTHENTICATED: i32 = 16;

mod protocol;
mod response;

pub(super) use protocol::{OtlpHttpSignal, ResponseEncoding, request_encoding};
pub(super) use response::{
    failure, ingest_response, ingest_trace_response, service_response_with_encoding,
    trace_service_response_with_encoding,
};

#[cfg(test)]
pub(crate) use response::{RpcStatus, success, trace_success};

#[cfg(test)]
#[path = "otlp_http/tests/mod.rs"]
mod tests;

pub(super) fn receive(
    stream: &mut TcpStream,
    head: RequestHead,
    services: &ServiceHandle,
) -> Result<Response, Response> {
    let (request_encoding, response_encoding) = request_encoding(
        head.content_type.as_deref(),
        head.content_encoding.as_deref(),
        OtlpHttpSignal::Logs,
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
    let result = if head.path == "/otlp/v1/logs" {
        services.ingest_encoded_loki_otlp_logs(context, request_encoding, body, reservation)
    } else {
        services.ingest_encoded_otlp_http_logs(context, request_encoding, body, reservation)
    };
    Ok(ingest_response(result, response_encoding))
}

pub(super) fn receive_traces(
    stream: &mut TcpStream,
    head: RequestHead,
    services: &ServiceHandle,
) -> Result<Response, Response> {
    let (request_encoding, response_encoding) = request_encoding(
        head.content_type.as_deref(),
        head.content_encoding.as_deref(),
        OtlpHttpSignal::Traces,
    )?;
    let bearer = head.bearer.ok_or_else(|| {
        failure(
            401,
            UNAUTHENTICATED,
            "OTLP Traces request authentication was rejected",
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
                "OTLP Traces request authentication was rejected",
                response_encoding,
            )
        })?
        .unwrap_or_else(CompatibilityHints::none);
    let context = services
        .authorize_traces_with_hints(&bearer, hints)
        .map_err(|_| {
            failure(
                401,
                UNAUTHENTICATED,
                "OTLP Traces request authentication was rejected",
                response_encoding,
            )
        })?;
    let admission = services
        .admit_traces(context)
        .map_err(|failure| trace_service_response_with_encoding(failure, response_encoding))?;
    let (encoded_limit, decoded_limit) = services
        .traces_transport_limits()
        .map_err(|failure| trace_service_response_with_encoding(failure, response_encoding))?;
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
            "OTLP Traces request exceeds the receiver limit",
            response_encoding,
        ));
    }
    let body = read_body(stream, head.content_length, body_limit).map_err(|_| {
        failure(
            400,
            INVALID_ARGUMENT,
            "OTLP Traces request body could not be read",
            response_encoding,
        )
    })?;
    let reservation = admission
        .take()
        .map_err(|failure| trace_service_response_with_encoding(failure, response_encoding))?;
    let trace_encoding = match request_encoding {
        OtlpLogsRequestEncoding::Protobuf => OtlpTracesRequestEncoding::Protobuf,
        OtlpLogsRequestEncoding::GzipProtobuf => OtlpTracesRequestEncoding::GzipProtobuf,
        OtlpLogsRequestEncoding::Json => OtlpTracesRequestEncoding::Json,
        OtlpLogsRequestEncoding::GzipJson => OtlpTracesRequestEncoding::GzipJson,
    };
    Ok(ingest_trace_response(
        services.ingest_encoded_otlp_http_traces(context, trace_encoding, body, reservation),
        response_encoding,
    ))
}
