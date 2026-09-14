use std::io::{Read, Write};

use positron_api::generated::{ApiError, CapabilityResponse};
use positron_governance::CompatibilityHints;
use zeroize::{Zeroize, Zeroizing};

use super::super::TrustedProxy;
use crate::HealthWarning;

const MAX_HEADER_BYTES: usize = 8 * 1024;

pub(in crate::native_host) struct RequestHead {
    pub(in crate::native_host) method: String,
    pub(in crate::native_host) path: String,
    pub(in crate::native_host) content_length: usize,
    pub(in crate::native_host) bearer: Option<String>,
    pub(in crate::native_host) content_type: Option<String>,
    pub(in crate::native_host) content_encoding: Option<String>,
    pub(in crate::native_host) tenant_hint: Option<String>,
    pub(in crate::native_host) forwarded_for: Option<String>,
    pub(in crate::native_host) forwarded_actor: Option<String>,
}

impl RequestHead {
    pub(in crate::native_host) fn compatibility_hints(
        &self,
        peer: std::net::SocketAddr,
        trusted_proxy: Option<TrustedProxy>,
    ) -> Result<CompatibilityHints, ()> {
        let forwarded = self.forwarded_for.is_some() || self.forwarded_actor.is_some();
        match trusted_proxy {
            Some(policy) if forwarded => {
                if !policy.validates(peer, self.forwarded_for.as_deref()) {
                    return Err(());
                }
                CompatibilityHints::trusted_proxy(
                    self.tenant_hint.as_deref(),
                    self.forwarded_actor.as_deref(),
                )
                .map_err(|_| ())
            },
            Some(_) | None => self
                .tenant_hint
                .as_deref()
                .map(CompatibilityHints::external_tenant_alias)
                .transpose()
                .map_err(|_| ())
                .map(|hints| hints.unwrap_or_else(CompatibilityHints::none)),
        }
    }
}

pub(in crate::native_host) fn read_head<S: Read>(stream: &mut S) -> Result<RequestHead, Response> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(512));
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
    let mut authorization_seen = false;
    let mut content_type = None;
    let mut content_encoding = None;
    let mut tenant_hint = None;
    let mut forwarded_for = None;
    let mut forwarded_actor = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| Response::empty(400))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Response::empty(400));
            }
            content_length = Some(value.parse().map_err(|_| Response::empty(400))?);
        } else if name.eq_ignore_ascii_case("authorization") {
            if authorization_seen {
                return Err(Response::empty(400));
            }
            authorization_seen = true;
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
        } else if name.eq_ignore_ascii_case("x-forwarded-for") {
            if forwarded_for.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_for = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("x-forwarded-user")
            || name.eq_ignore_ascii_case("x-forwarded-service")
        {
            if forwarded_actor.is_some() {
                return Err(Response::empty(400));
            }
            forwarded_actor = Some(value.to_owned());
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
        forwarded_for,
        forwarded_actor,
    })
}

pub(in crate::native_host) fn read_body<S: Read>(
    stream: &mut S,
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

pub(in crate::native_host) fn health_response(
    healthy: bool,
    label: &'static str,
    warning: Option<HealthWarning>,
) -> Response {
    let warnings = match warning {
        Some(HealthWarning::PublicPlaintextApi) => "[\"public_plaintext_api\"]",
        None => "[]",
    };
    if healthy {
        Response::json(
            200,
            format!("{{\"status\":\"{label}\",\"warnings\":{warnings}}}"),
        )
    } else {
        Response::json(
            503,
            format!("{{\"status\":\"not_{label}\",\"warnings\":{warnings}}}"),
        )
    }
}

pub(in crate::native_host) fn capability_response(
    result: Result<CapabilityResponse, ApiError>,
) -> Response {
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

pub(in crate::native_host) struct Response {
    pub(in crate::native_host) status: u16,
    pub(in crate::native_host) content_type: &'static str,
    pub(in crate::native_host) body: Vec<u8>,
    pub(in crate::native_host) retry_after_seconds: Option<u32>,
}

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl Response {
    pub(in crate::native_host) fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: Vec::new(),
            retry_after_seconds: None,
        }
    }

    pub(in crate::native_host) fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: body.into_bytes(),
            retry_after_seconds: None,
        }
    }

    pub(in crate::native_host) fn protobuf(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/x-protobuf",
            body,
            retry_after_seconds: None,
        }
    }

    pub(in crate::native_host) const fn with_retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    #[cfg(test)]
    pub(in crate::native_host) const fn status(&self) -> u16 {
        self.status
    }

    #[cfg(test)]
    pub(in crate::native_host) const fn content_type(&self) -> &'static str {
        self.content_type
    }

    #[cfg(test)]
    pub(in crate::native_host) fn body(&self) -> &[u8] {
        &self.body
    }

    #[cfg(test)]
    pub(in crate::native_host) const fn retry_after_seconds(&self) -> Option<u32> {
        self.retry_after_seconds
    }
}

pub(in crate::native_host) fn write_response<S: Write>(
    stream: &mut S,
    response: Response,
) -> Result<(), std::io::Error> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::serve_tls_api_connection;

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn request(path: &str) -> Self {
            Self {
                input: Cursor::new(
                    format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n")
                        .into_bytes(),
                ),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn tls_api_dispatch_reaches_each_existing_authenticated_route() {
        let health = crate::health::ProcessState::starting().health();
        for path in [
            positron_api::tenant_aliases::HTTP_PATH,
            positron_api::policy::HTTP_EXPLAIN_PATH,
            positron_api::policy::HTTP_ACTIVATE_PATH,
        ] {
            let mut stream = MemoryStream::request(path);
            assert!(serve_tls_api_connection(&mut stream, &health, None).is_ok());
            let response = std::str::from_utf8(&stream.output).expect("HTTP response");
            assert!(
                response.starts_with("HTTP/1.1 503 Service Unavailable"),
                "TLS dispatcher did not reach {path}: {response}"
            );
        }
    }
}
