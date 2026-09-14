//! Native HTTP listener framing with separately owned routing and I/O boundaries.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::TrustedProxy;
use crate::{HealthState, ListenerRole, ServiceHandle};

mod dispatch;
mod io;
mod adapters {
    pub(in crate::native_host::native_http) mod policy;
    pub(in crate::native_host::native_http) mod tenant;
}

pub(super) use io::{RequestHead, Response, read_body};

pub(super) fn serve_connection(
    stream: &mut TcpStream,
    role: ListenerRole,
    peer: std::net::SocketAddr,
    trusted_proxy: Option<TrustedProxy>,
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
    let result = serve_checked(stream, role, peer, trusted_proxy, health, services);
    if let Err(response) = result {
        io::write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

pub(super) struct ConnectionFailure;

pub(super) fn serve_tls_api_connection<S: Read + Write>(
    stream: &mut S,
    health: &HealthState,
    services: Option<&ServiceHandle>,
) -> Result<(), ConnectionFailure> {
    let result = (|| {
        let head = io::read_head(stream)?;
        let response = dispatch::route_tls_api(stream, head, health, services)?;
        io::write_response(stream, response).map_err(|_| Response::empty(500))
    })();
    if let Err(response) = result {
        io::write_response(stream, response).map_err(|_| ConnectionFailure)?;
    }
    Ok(())
}

fn serve_checked(
    stream: &mut TcpStream,
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
