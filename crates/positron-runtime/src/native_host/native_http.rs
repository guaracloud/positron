use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use positron_api::generated::{ApiError, CapabilityResponse};
use positron_ingest::IngestOutcome;

use crate::{HealthState, ListenerRole, Liveness, Readiness, ServiceFailure, ServiceHandle};

const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_OTLP_BODY_BYTES: usize = 1_048_576;
const MAX_API_BODY_BYTES: usize = positron_api::generated::MAX_PUBLIC_REQUEST_BYTES;

pub(super) fn serve_connection(
    stream: &mut TcpStream,
    role: ListenerRole,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    if stream
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
            let bearer = head.bearer.ok_or_else(|| Response::empty(401))?;
            let body = read_body(stream, head.content_length, MAX_OTLP_BODY_BYTES)?;
            Ok(ingest_response(services.ingest_otlp_logs(&bearer, body)))
        },
        (ListenerRole::Operations, _, "/health/live" | "/health/ready")
        | (ListenerRole::Api, _, "/v1/capabilities:negotiate")
        | (ListenerRole::OtlpHttp, _, "/v1/logs") => Ok(Response::empty(405)),
        (ListenerRole::Control, _, _) | (_, _, _) => Ok(Response::empty(404)),
    }
}

struct RequestHead {
    method: String,
    path: String,
    content_length: usize,
    bearer: Option<String>,
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
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Response::empty(400));
        }
    }
    Ok(RequestHead {
        method: method.to_owned(),
        path: path.to_owned(),
        content_length: content_length.unwrap_or(0),
        bearer,
    })
}

fn read_body(stream: &mut TcpStream, length: usize, maximum: usize) -> Result<Vec<u8>, Response> {
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

fn ingest_response(
    result: Result<positron_ingest::IngestRequestOutcome, ServiceFailure>,
) -> Response {
    match result {
        Ok(outcome) => match outcome.terminal_failure() {
            Some(IngestOutcome::Retryable(_)) => {
                Response::json(503, "{\"outcome\":\"retryable\"}".into())
            },
            Some(IngestOutcome::Permanent(_)) => {
                Response::json(422, "{\"outcome\":\"rejected\"}".into())
            },
            Some(IngestOutcome::Ambiguous(_)) => {
                Response::json(500, "{\"outcome\":\"ambiguous\"}".into())
            },
            Some(IngestOutcome::Full(_) | IngestOutcome::Partial(_)) => {
                Response::json(500, "{\"outcome\":\"internal\"}".into())
            },
            None => Response::json(
                200,
                format!(
                    "{{\"accepted\":{},\"rejected\":{}}}",
                    outcome.accepted_records(),
                    outcome.permanently_rejected_records()
                ),
            ),
        },
        Err(ServiceFailure::Unauthorized) => Response::empty(401),
        Err(ServiceFailure::CapacityUnavailable) => Response::empty(429),
        Err(ServiceFailure::InvalidRequest) => Response::empty(400),
        Err(ServiceFailure::KeyUnavailable | ServiceFailure::StorageUnavailable) => {
            Response::empty(503)
        },
        Err(ServiceFailure::Internal) => Response::json(500, "{\"outcome\":\"internal\"}".into()),
    }
}

struct Response {
    status: u16,
    body: String,
}

impl Response {
    fn empty(status: u16) -> Self {
        Self {
            status,
            body: String::new(),
        }
    }

    fn json(status: u16, body: String) -> Self {
        Self { status, body }
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
        422 => "Unprocessable Content",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(response.body.as_bytes())
}
