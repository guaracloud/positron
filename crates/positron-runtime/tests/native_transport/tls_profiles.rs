use super::*;

#[test]
fn api_tls_profile_rejects_missing_or_invalid_identity_material() {
    let missing = ApiTransportProfile::tls(
        PathBuf::from("/tmp/positron-missing-api-certificate.pem"),
        PathBuf::from("/tmp/positron-missing-api-key.pem"),
    );
    assert!(missing.is_err());

    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let invalid_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    assert!(ApiTransportProfile::tls(certificate, invalid_key).is_err());
}

#[test]
fn public_api_binding_requires_tls_or_the_exact_plaintext_opt_out()
-> Result<(), Box<dyn std::error::Error>> {
    let control = PathBuf::from("/tmp/positron-public-api.sock");
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let public = "192.0.2.1:8443".parse()?;
    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    assert!(
        NativeBindings::new(
            control.clone(),
            loopback,
            public,
            loopback,
            loopback,
            loopback
        )
        .is_err()
    );
    assert!(
        NativeBindings::new_with_api_transport(
            control.clone(),
            loopback,
            public,
            loopback,
            loopback,
            loopback,
            ApiTransportProfile::tls(certificate, private_key)?,
        )
        .is_ok()
    );
    assert!(
        NativeBindings::new_with_api_transport(
            control,
            loopback,
            public,
            loopback,
            loopback,
            loopback,
            ApiTransportProfile::plaintext_opt_out(),
        )
        .is_ok(),
        "an explicit plaintext listener profile admits a public API address"
    );
    Ok(())
}

#[test]
fn native_bindings_reject_unsafe_and_colliding_endpoints() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = live_test_guard();
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let wildcard = "0.0.0.0:1".parse()?;
    assert!(TrustedProxy::exact_peer(Ipv4Addr::LOCALHOST.into(), 0).is_err());
    assert!(
        NativeBindings::new(
            PathBuf::from("relative.sock"),
            loopback,
            loopback,
            loopback,
            loopback,
            loopback,
        )
        .is_err()
    );
    assert!(
        NativeBindings::new(
            PathBuf::from("/tmp/control.sock"),
            wildcard,
            loopback,
            loopback,
            loopback,
            loopback
        )
        .is_err()
    );

    let roots = TestRoots::new("collision")?;
    let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let occupied_address = occupied.local_addr()?;
    let bindings = NativeBindings::new(
        roots.parent.join("collision.sock"),
        occupied_address,
        loopback,
        loopback,
        loopback,
        loopback,
    )?;
    let host = NativeHost::new(bindings);
    let paths = roots.paths()?;
    let result = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    );
    assert!(matches!(
        result,
        Err(positron_runtime::ExitOutcome::ListenerUnavailable(
            positron_runtime::ListenerRole::Operations
        ))
    ));
    Ok(())
}
