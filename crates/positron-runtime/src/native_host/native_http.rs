//! Native HTTP listener framing with separately owned routing and I/O boundaries.

use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::TrustedProxy;
use crate::{ConnectionProtection, HealthState, ListenerRole, ServiceHandle};

mod dispatch;
mod io;
mod adapters {
    pub(in crate::native_host::native_http) mod policy;
    pub(in crate::native_host::native_http) mod tenant;
}

pub(super) use io::{RequestHead, Response, read_body};

pub(super) const MAX_API_BODY_BYTES: usize = positron_api::generated::MAX_PUBLIC_REQUEST_BYTES;

pub(super) fn api_body_limit(method: &str, path: &str) -> usize {
    dispatch::api_body_limit(method, path)
}

pub(super) fn route_buffered_api(
    head: RequestHead,
    body: Vec<u8>,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Response {
    let mut stream = Cursor::new(body);
    match dispatch::route(
        &mut stream,
        ListenerRole::Api,
        peer,
        trusted_proxy,
        head,
        health,
        services,
    ) {
        Ok(response) | Err(response) => response,
    }
}

pub(super) use io::head_from_http_parts;

pub(super) fn serve_connection<S: Read + Write + TimeoutStream>(
    stream: &mut S,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
    protection: ConnectionProtection,
) -> Result<(), ConnectionFailure> {
    let result = serve_checked(
        stream,
        role,
        peer,
        trusted_proxy,
        health,
        services,
        protection,
    );
    if let Err(response) = result {
        io::write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

pub(super) struct ConnectionFailure;

pub(super) fn serve_tls_connection<S: Read + Write + TimeoutStream>(
    stream: &mut S,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
    protection: ConnectionProtection,
) -> Result<(), ConnectionFailure> {
    let result = serve_checked(
        stream,
        role,
        peer,
        trusted_proxy,
        health,
        services,
        protection,
    );
    if let Err(response) = result {
        io::write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

fn serve_checked<S: Read + Write + TimeoutStream>(
    stream: &mut S,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
    protection: ConnectionProtection,
) -> Result<(), Response> {
    let started = Instant::now();
    let mut header = DeadlineStream::new(
        stream,
        started + protection.header_deadline(),
        protection.idle_deadline(),
    );
    let head = io::read_head(&mut header)?;
    let body_deadline = Instant::now() + protection.body_deadline();
    let request_deadline = started + protection.request_deadline();
    let deadline = body_deadline.min(request_deadline);
    let mut request =
        DeadlineStream::new(header.into_inner(), deadline, protection.idle_deadline());
    let response = dispatch::route(
        &mut request,
        role,
        peer,
        trusted_proxy,
        head,
        health,
        services,
    )?;
    if Instant::now() > request_deadline {
        return Err(Response::empty(408));
    }
    io::write_response(stream, response).map_err(|_| Response::empty(500))
}

pub(super) trait TimeoutStream {
    fn set_timeouts(&mut self, timeout: Duration) -> std::io::Result<()>;
}

impl TimeoutStream for TcpStream {
    fn set_timeouts(&mut self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}

impl TimeoutStream for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_timeouts(&mut self, timeout: Duration) -> std::io::Result<()> {
        self.sock.set_read_timeout(Some(timeout))?;
        self.sock.set_write_timeout(Some(timeout))
    }
}

struct DeadlineStream<'stream, S> {
    stream: &'stream mut S,
    deadline: Instant,
    idle_deadline: Duration,
}

impl<'stream, S> DeadlineStream<'stream, S> {
    fn new(stream: &'stream mut S, deadline: Instant, idle_deadline: Duration) -> Self {
        Self {
            stream,
            deadline,
            idle_deadline,
        }
    }

    fn into_inner(self) -> &'stream mut S {
        self.stream
    }
}

impl<S: TimeoutStream> DeadlineStream<'_, S> {
    fn configure_next_io(&mut self) -> std::io::Result<()> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request deadline elapsed",
            ));
        }
        self.stream.set_timeouts(remaining.min(self.idle_deadline))
    }
}

impl<S: Read + TimeoutStream> Read for DeadlineStream<'_, S> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.configure_next_io()?;
        self.stream.read(buffer)
    }
}

impl<S: Write + TimeoutStream> Write for DeadlineStream<'_, S> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.configure_next_io()?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.configure_next_io()?;
        self.stream.flush()
    }
}
