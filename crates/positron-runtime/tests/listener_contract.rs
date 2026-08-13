//! Public listener endpoint contract.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};

use positron_runtime::{BoundEndpoint, ExitOutcome, ListenerFailure, ListenerRole};

#[test]
fn public_listener_endpoints_reject_unsafe_shapes() {
    assert_eq!(
        BoundEndpoint::control(PathBuf::from("relative.sock")),
        Err(ListenerFailure::InvalidEndpoint)
    );
    assert_eq!(
        BoundEndpoint::tcp(
            ListenerRole::Control,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))
        ),
        Err(ListenerFailure::InvalidEndpoint)
    );
    assert_eq!(
        BoundEndpoint::tcp(
            ListenerRole::Api,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1))
        ),
        Err(ListenerFailure::InvalidEndpoint)
    );
    assert_eq!(
        format!("{}", ListenerFailure::BindUnavailable),
        "listener activation failed"
    );
    let control = BoundEndpoint::control(PathBuf::from("/tmp/control.sock")).expect("control");
    assert_eq!(control.control_path(), Some(Path::new("/tmp/control.sock")));
    assert_eq!(control.socket_address(), None);
    let api = BoundEndpoint::tcp(
        ListenerRole::Api,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)),
    )
    .expect("api");
    assert_eq!(api.control_path(), None);
    assert_eq!(api.socket_address().map(|address| address.port()), Some(1));
    assert_eq!(
        format!("{}", ExitOutcome::Graceful),
        "Positron process exited"
    );
    let error: &dyn std::error::Error = &ExitOutcome::Forced;
    assert!(error.source().is_none());
}
