use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use positron_api::generated::{ApiError, CapabilityResponse};

use crate::{HealthState, ListenerRole, Liveness, Readiness, ServiceHandle};

const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_API_BODY_BYTES: usize = positron_api::generated::MAX_PUBLIC_REQUEST_BYTES;

pub(super) fn serve_connection(
    stream: &mut TcpStream,
    role: ListenerRole,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    if stream.set_nonblocking(false).is_err()
        || stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .is_err()
    {
        return Err(ConnectionFailure);
    }
    let result = serve_checked(stream, role, health, services);
    if let Err(response) = result {
        write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

pub(super) struct ConnectionFailure;

fn serve_checked(
    stream: &mut TcpStream,
    role: ListenerRole,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), Response> {
    let head = read_head(stream)?;
    let response = route(stream, role, head, health, services)?;
    write_response(stream, response).map_err(|_| Response::empty(500))
}

fn route(
    stream: &mut TcpStream,
    role: ListenerRole,
    head: RequestHead,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<Response, Response> {
    match (role, head.method.as_str(), head.path.as_str()) {
        (ListenerRole::Operations, "GET", "/health/live") => {
            Ok(health_response(health.liveness() == Liveness::Live, "live"))
        },
        (ListenerRole::Operations, "GET", "/health/ready") => Ok(health_response(
            health.readiness() == Readiness::Ready,
            "ready",
        )),
        (ListenerRole::Api, "POST", "/v1/capabilities:negotiate") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            let body = read_body(stream, head.content_length, MAX_API_BODY_BYTES)?;
            Ok(capability_response(services.negotiate_capability(&body)))
        },
        (ListenerRole::OtlpHttp, "POST", "/v1/logs") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::otlp_http::receive(stream, head, services)
        },
        (ListenerRole::LokiPush, "POST", "/loki/api/v1/push") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::loki_http::receive_push(stream, head, services)
        },
        (ListenerRole::LokiPush, "POST", "/otlp/v1/logs") => {
            let services = services.ok_or_else(|| Response::empty(503))?;
            super::otlp_http::receive(stream, head, services)
        },
        (ListenerRole::Operations, _, "/health/live" | "/health/ready")
        | (ListenerRole::Api, _, "/v1/capabilities:negotiate")
        | (ListenerRole::OtlpHttp, _, "/v1/logs") => Ok(Response::empty(405)),
        (ListenerRole::LokiPush, _, "/loki/api/v1/push" | "/otlp/v1/logs") => {
            Ok(Response::empty(405))
        },
        (ListenerRole::Control, _, _) | (_, _, _) => Ok(Response::empty(404)),
    }
}

pub(super) struct RequestHead {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) content_length: usize,
    pub(super) bearer: Option<String>,
    pub(super) content_type: Option<String>,
    pub(super) content_encoding: Option<String>,
    pub(super) tenant_hint: Option<String>,
}

fn read_head(stream: &mut TcpStream) -> Result<RequestHead, Response> {
    let mut bytes = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER_BYTES {
            return Err(Response::empty(431));
        }
        stream
            .read_exact(&mut byte)
            .map_err(|_| Response::empty(400))?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Response::empty(400))?;
    let mut lines = text.split("\r\n");
    let mut request = lines.next().ok_or_else(|| Response::empty(400))?.split(' ');
    let method = request.next().ok_or_else(|| Response::empty(400))?;
    let path = request.next().ok_or_else(|| Response::empty(400))?;
    if request.next() != Some("HTTP/1.1") || request.next().is_some() {
        return Err(Response::empty(400));
    }
    let mut content_length = None;
    let mut bearer = None;
    let mut content_type = None;
    let mut content_encoding = None;
    let mut tenant_hint = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| Response::empty(400))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Response::empty(400));
            }
            content_length = Some(value.parse().map_err(|_| Response::empty(400))?);
        } else if name.eq_ignore_ascii_case("authorization") {
            bearer = value.strip_prefix("Bearer ").map(ToOwned::to_owned);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(Response::empty(400));
            }
            content_type = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding.is_some() {
                return Err(Response::empty(400));
            }
            content_encoding = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-scope-orgid") {
            if tenant_hint.is_some() {
                return Err(Response::empty(400));
            }
            tenant_hint = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Response::empty(400));
        }
    }
    Ok(RequestHead {
        method: method.to_owned(),
        path: path.to_owned(),
        content_length: content_length.unwrap_or(0),
        bearer,
        content_type,
        content_encoding,
        tenant_hint,
    })
}

pub(super) fn read_body(
    stream: &mut TcpStream,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, Response> {
    if length > maximum {
        return Err(Response::empty(413));
    }
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|_| Response::empty(400))?;
    Ok(body)
}

fn health_response(healthy: bool, label: &'static str) -> Response {
    if healthy {
        Response::json(200, format!("{{\"status\":\"{label}\"}}"))
    } else {
        Response::json(503, format!("{{\"status\":\"not_{label}\"}}"))
    }
}

fn capability_response(result: Result<CapabilityResponse, ApiError>) -> Response {
    match result {
        Ok(response) => {
            let refusal = response.refusal().map_or_else(
                || "null".to_owned(),
                |error| {
                    format!(
                        "{{\"code\":{},\"retry_class\":{},\"completion_state\":{},\"source\":{},\"safe_detail\":{}}}",
                        error.code() as u32,
                        error.retry_class() as u32,
                        error.completion_state() as u32,
                        error.source() as u32,
                        error.safe_detail() as u32
                    )
                },
            );
            Response::json(
                200,
                format!(
                    "{{\"api_major\":{},\"schema_digest\":\"{}\",\"availability\":{},\"refusal\":{},\"deprecation\":{},\"capability\":{}}}",
                    response.api_major().major(),
                    response.schema_digest().as_str(),
                    response.availability() as u32,
                    refusal,
                    response.deprecation() as u32,
                    response.capability() as u32
                ),
            )
        },
        Err(error) => Response::json(400, format!("{{\"code\":{}}}", error.code() as u32)),
    }
}

pub(super) struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    retry_after_seconds: Option<u32>,
}

impl Response {
    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: Vec::new(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into_bytes(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn protobuf(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/x-protobuf",
            body,
            retry_after_seconds: None,
        }
    }

    pub(super) const fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    #[cfg(test)]
    pub(super) const fn status(&self) -> u16 {
        self.status
    }

    #[cfg(test)]
    pub(super) const fn content_type(&self) -> &'static str {
        self.content_type
    }

    #[cfg(test)]
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    #[cfg(test)]
    pub(super) const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }
}

fn write_response(stream: &mut TcpStream, response: Response) -> Result<(), std::io::Error> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let retry_after = response
        .retry_after_seconds
        .map_or_else(String::new, |seconds| format!("Retry-After: {seconds}\r\n"));
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len(),
        retry_after
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&response.body)
}
