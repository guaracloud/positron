//! Native HTTP listener framing with separately owned routing and I/O boundaries.

use std::io::{Cursor, Read, Write};

use super::TrustedProxy;
use crate::{HealthState, ListenerRole, ServiceHandle};

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

pub(super) fn serve_connection<S: Read + Write>(
    stream: &mut S,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    let result = serve_checked(stream, role, peer, trusted_proxy, health, services);
    if let Err(response) = result {
        io::write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

pub(super) struct ConnectionFailure;

pub(super) fn serve_tls_connection<S: Read + Write>(
    stream: &mut S,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    let result = serve_checked(stream, role, peer, trusted_proxy, health, services);
    if let Err(response) = result {
        io::write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

fn serve_checked<S: Read + Write>(
    stream: &mut S,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), Response> {
    let head = io::read_head(stream)?;
    let response = dispatch::route(stream, role, peer, trusted_proxy, head, health, services)?;
    io::write_response(stream, response).map_err(|_| Response::empty(500))
}
