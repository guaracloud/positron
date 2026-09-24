//! Public listener endpoint contract.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};

use positron_runtime::{
    BoundEndpoint, ExitOutcome, ListenerFailure, ListenerProfile, ListenerRole, ListenerTransport,
    ValidatedListenerSet,
};

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
    assert!(
        BoundEndpoint::tcp(
            ListenerRole::Api,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1))
        )
        .is_ok(),
        "transport policy later decides whether this API address is safe"
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

#[test]
fn complete_listener_candidates_require_each_role_and_explicit_public_transport()
-> Result<(), Box<dyn std::error::Error>> {
    let control = ListenerProfile::control(PathBuf::from("/run/positron/control.sock"))?;
    let operations = ListenerProfile::network(
        ListenerRole::Operations,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9_090)),
        ListenerTransport::PlaintextOptOut,
    )?;
    let api = ListenerProfile::network(
        ListenerRole::Api,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8_080)),
        ListenerTransport::Tls,
    )?;
    let otlp_grpc = ListenerProfile::network(
        ListenerRole::OtlpGrpc,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4_317)),
        ListenerTransport::PlaintextOptOut,
    )?;
    let otlp_http = ListenerProfile::network(
        ListenerRole::OtlpHttp,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4_318)),
        ListenerTransport::PlaintextOptOut,
    )?;
    let loki_push = ListenerProfile::network(
        ListenerRole::LokiPush,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3_100)),
        ListenerTransport::PlaintextOptOut,
    )?;

    let complete =
        ValidatedListenerSet::new([control, operations, api, otlp_grpc, otlp_http, loki_push])?;
    assert_eq!(complete.len(), 6);
    let explicit_public_plaintext = ListenerProfile::network(
        ListenerRole::OtlpGrpc,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 4_317)),
        ListenerTransport::PlaintextOptOut,
    )?;
    assert!(explicit_public_plaintext.has_plaintext_opt_out());
    assert!(
        ValidatedListenerSet::new([
            ListenerProfile::control(PathBuf::from("/run/positron/control.sock"))?,
            ListenerProfile::network(
                ListenerRole::Operations,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9_090)),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::Api,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_080)),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::OtlpGrpc,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4_317)),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::OtlpHttp,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4_318)),
                ListenerTransport::PlaintextOptOut,
            )?,
            ListenerProfile::network(
                ListenerRole::OtlpHttp,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3_100)),
                ListenerTransport::PlaintextOptOut,
            )?,
        ])
        .is_err()
    );
    Ok(())
}
