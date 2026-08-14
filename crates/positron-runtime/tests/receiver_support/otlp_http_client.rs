use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use opentelemetry_http::{Bytes, HttpClient, HttpError};

#[derive(Clone, Copy)]
pub(super) struct SocketHttpClient(pub(super) SocketAddr);

impl Debug for SocketHttpClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SocketHttpClient")
    }
}

#[async_trait::async_trait]
impl HttpClient for SocketHttpClient {
    async fn send_bytes(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let mut stream = TcpStream::connect_timeout(&self.0, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut wire = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in &parts.headers {
            if name == http::header::HOST || name == http::header::CONTENT_LENGTH {
                continue;
            }
            wire.push_str(name.as_str());
            wire.push_str(": ");
            wire.push_str(value.to_str()?);
            wire.push_str("\r\n");
        }
        wire.push_str("\r\n");
        stream.write_all(wire.as_bytes())?;
        stream.write_all(&body)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let separator = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or_else(|| std::io::Error::other("HTTP response head missing"))?;
        let status = std::str::from_utf8(&response[..separator])?
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| std::io::Error::other("HTTP response status missing"))?
            .parse::<u16>()?;
        Ok(http::Response::builder()
            .status(status)
            .body(Bytes::copy_from_slice(&response[(separator + 4)..]))?)
    }
}
