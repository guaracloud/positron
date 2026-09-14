use super::*;
use std::net::{Ipv4Addr, SocketAddr};

#[test]
fn operations_health_exposes_plaintext_transport_warning_without_degrading_readiness()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let plaintext_roots = TestRoots::new("plaintext-health-warning")?;
    let plaintext_paths = plaintext_roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &plaintext_paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let plaintext_host = NativeHost::new(bindings(&plaintext_roots, "plaintext-health-warning")?);
    let plaintext = ApplicationRuntime::start(
        ServeConfiguration::new(plaintext_paths, InitializationMode::ExistingOnly)
            .with_public_plaintext_api_intent(PublicPlaintextApiStartupIntent::configuration_file(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8_080)),
            )),
        HostInputs::new(&plaintext_host, &plaintext_host),
    )?;
    let plaintext_operations = address(
        &plaintext.bound_endpoints(),
        positron_runtime::ListenerRole::Operations,
    )?;
    let plaintext_health = http(plaintext_operations, "GET", "/health/ready", &[], &[])?;
    assert_status(plaintext_health.clone(), 200);
    assert!(plaintext_health.contains("\"status\":\"ready\""));
    assert!(plaintext_health.contains("\"warnings\":[\"public_plaintext_api\"]"));
    assert_eq!(
        plaintext.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );

    let tls_roots = TestRoots::new("tls-health-warning")?;
    let tls_paths = tls_roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &tls_paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let tls_host = NativeHost::new(
        bindings(&tls_roots, "tls-health-warning")?
            .with_api_transport(ApiTransportProfile::tls(certificate, private_key)?)?,
    );
    let tls = ApplicationRuntime::start(
        ServeConfiguration::new(tls_paths, InitializationMode::ExistingOnly),
        HostInputs::new(&tls_host, &tls_host),
    )?;
    let tls_operations = address(
        &tls.bound_endpoints(),
        positron_runtime::ListenerRole::Operations,
    )?;
    let tls_health = http(tls_operations, "GET", "/health/ready", &[], &[])?;
    assert_status(tls_health.clone(), 200);
    assert!(tls_health.contains("\"status\":\"ready\""));
    assert!(tls_health.contains("\"warnings\":[]"));
    assert_eq!(
        tls.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn loopback_otlp_is_authenticated_durable_and_observable_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("loopback")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let first_bindings = bindings(&roots, "first")?;
    let first_host = NativeHost::new(first_bindings);
    let first = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&first_host, &first_host),
    )?;
    let endpoints = first.bound_endpoints();
    let operations = address(&endpoints, positron_runtime::ListenerRole::Operations)?;
    let api = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let otlp = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;

    assert_status(http(operations, "GET", "/health/ready", &[], &[])?, 200);
    let capability = http(
        api,
        "POST",
        "/v1/capabilities:negotiate",
        &[],
        br#"{"api_major":1,"capability":1}"#,
    )?;
    assert_status(capability.clone(), 200);
    assert!(capability.contains("\"availability\":1"));

    let unauthorized = http(
        otlp,
        "POST",
        "/v1/logs",
        &[("Content-Type", "application/x-protobuf")],
        &[0xff],
    )?;
    assert_status(unauthorized, 401);
    let untrusted_forwarded_identity = http(
        otlp,
        "POST",
        "/v1/logs",
        &[
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-User", "forged-tenant-user"),
            ("X-Forwarded-Authorization", "Bearer pos_forged"),
        ],
        &[0xff],
    )?;
    assert_status(untrusted_forwarded_identity, 401);
    let body = otlp_body("durable-loopback");
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("ingest secret missing")?
    );
    let accepted = http(
        otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
        ],
        &body,
    )?;
    assert_status(accepted.clone(), 200);
    assert!(accepted.contains("Content-Type: application/x-protobuf"));

    let query_secret = claim
        .query_secret()
        .ok_or("query secret missing")?
        .to_owned();
    let ingest_secret = claim
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    drop(first);
    assert!(TcpStream::connect_timeout(&otlp, Duration::from_millis(100)).is_err());

    let second_bindings = bindings(&roots, "second")?;
    let second_host = NativeHost::new(second_bindings);
    let second = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&second_host, &second_host),
    )?;
    let bodies = second
        .services()
        .ok_or("serving process omitted services")?
        .query_log_bodies(
            &query_secret,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                .with_cpu_work_units(15)?,
        )?;
    assert_eq!(bodies, ["durable-loopback"]);
    assert!(matches!(
        second.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    assert!(!ingest_secret.is_empty());
    Ok(())
}

#[test]
fn configured_proxy_metadata_requires_the_exact_peer_and_fixed_hop_before_ingest()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("trusted-proxy-attribution")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("ingest secret missing")?
    );
    let query_secret = claim
        .query_secret()
        .ok_or("query secret missing")?
        .to_owned();
    let policy = TrustedProxy::exact_peer(Ipv4Addr::LOCALHOST.into(), 1)?;
    let host = NativeHost::new(bindings(&roots, "trusted-proxy")?.with_trusted_proxy(policy));
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let otlp = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::OtlpHttp,
    )?;

    let body = otlp_body("trusted-proxy-attribution");
    let accepted = http(
        otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-For", "198.51.100.24"),
            ("X-Forwarded-User", "proxied-operator"),
            ("X-Forwarded-Authorization", "Bearer pos_forged"),
        ],
        &body,
    )?;
    assert_status(accepted, 200);

    let wrong_hops = http(
        otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-For", "198.51.100.24, 198.51.100.25"),
            ("X-Forwarded-User", "proxied-operator"),
        ],
        &[0xff],
    )?;
    assert_status(wrong_hops, 401);

    let duplicate_forwarded_for = http(
        otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-For", "198.51.100.24"),
            ("X-Forwarded-For", "198.51.100.25"),
        ],
        &[0xff],
    )?;
    assert_status(duplicate_forwarded_for, 400);

    let conflicting_forwarded_actor = http(
        otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-For", "198.51.100.24"),
            ("X-Forwarded-User", "proxied-user"),
            ("X-Forwarded-Service", "proxied-service"),
        ],
        &[0xff],
    )?;
    assert_status(conflicting_forwarded_actor, 400);

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );

    let wrong_peer = TrustedProxy::exact_peer(Ipv4Addr::new(127, 0, 0, 2).into(), 1)?;
    let wrong_peer_host =
        NativeHost::new(bindings(&roots, "wrong-trusted-proxy")?.with_trusted_proxy(wrong_peer));
    let wrong_peer_process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&wrong_peer_host, &wrong_peer_host),
    )?;
    let wrong_peer_otlp = address(
        &wrong_peer_process.bound_endpoints(),
        positron_runtime::ListenerRole::OtlpHttp,
    )?;
    let rejected_peer = http(
        wrong_peer_otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-For", "198.51.100.24"),
            ("X-Forwarded-User", "proxied-operator"),
        ],
        &[0xff],
    )?;
    assert_status(rejected_peer, 401);
    assert_eq!(
        wrong_peer_process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );

    let unconfigured_host = NativeHost::new(bindings(&roots, "unconfigured-proxy")?);
    let unconfigured_process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&unconfigured_host, &unconfigured_host),
    )?;
    let unconfigured_otlp = address(
        &unconfigured_process.bound_endpoints(),
        positron_runtime::ListenerRole::OtlpHttp,
    )?;
    let unconfigured = http(
        unconfigured_otlp,
        "POST",
        "/v1/logs",
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/x-protobuf"),
            ("X-Forwarded-For", "198.51.100.24"),
            ("X-Forwarded-User", "forged-user"),
            ("X-Forwarded-Authorization", "Bearer pos_forged"),
        ],
        &otlp_body("unconfigured-forwarded-http"),
    )?;
    assert_status(unconfigured, 200);
    assert_eq!(
        unconfigured_process
            .services()
            .ok_or("serving process omitted services")?
            .query_log_bodies(
                &query_secret,
                "logs | range query_time 0 100 | limit 16",
                QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?
                    .with_cpu_work_units(15)?,
            )?,
        ["trusted-proxy-attribution", "unconfigured-forwarded-http"]
    );
    assert_eq!(
        unconfigured_process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn loopback_transport_enforces_bounded_http_and_typed_statuses()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("bounds")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "bounds")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let operations = address(&endpoints, positron_runtime::ListenerRole::Operations)?;
    let api = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let otlp = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;

    assert_status(http(operations, "GET", "/health/live", &[], &[])?, 200);
    assert_status(http(operations, "GET", "/health/ready", &[], &[])?, 200);
    assert_status(http(operations, "GET", "/missing", &[], &[])?, 404);
    assert_status(
        http(
            operations,
            "POST",
            "/v1/logs",
            &[("Authorization", "Bearer invalid")],
            &[0xff],
        )?,
        404,
    );
    assert_status_raw(
        operations,
        b"POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048576\r\n\r\n",
        404,
    )?;
    assert_status(
        http(
            operations,
            "POST",
            "/v1/capabilities:negotiate",
            &[],
            br#"{"api_major":1,"capability":1}"#,
        )?,
        404,
    );
    assert_status(http(api, "GET", "/health/ready", &[], &[])?, 404);
    assert_status(
        http(
            api,
            "POST",
            "/v1/logs",
            &[("Authorization", "Bearer invalid")],
            &[0xff],
        )?,
        404,
    );
    assert_status(http(otlp, "GET", "/health/live", &[], &[])?, 404);
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/capabilities:negotiate",
            &[],
            br#"{"api_major":1,"capability":1}"#,
        )?,
        404,
    );
    assert_status(
        http(api, "GET", "/v1/capabilities:negotiate", &[], &[])?,
        405,
    );
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.0\r\nHost: localhost\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        400,
    )?;
    assert_status(
        http(api, "POST", "/v1/capabilities:negotiate", &[], &[b'x'; 65])?,
        413,
    );
    assert_status(
        http(api, "POST", "/v1/capabilities:negotiate", &[], b"not-json")?,
        400,
    );
    let refused = http(
        api,
        "POST",
        "/v1/capabilities:negotiate",
        &[],
        br#"{"api_major":2,"capability":1}"#,
    )?;
    assert_status(refused.clone(), 200);
    assert!(refused.contains("\"refusal\":{"));
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\ninvalid-header\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\nContent-Length: invalid\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        api,
        b"POST /v1/capabilities:negotiate HTTP/1.1\r\nContent-Length: 5\r\n\r\nx",
        400,
    )?;
    let mut invalid_utf8 = b"GET /health/live HTTP/1.1\r\nX: ".to_vec();
    invalid_utf8.push(0xff);
    invalid_utf8.extend_from_slice(b"\r\n\r\n");
    assert_status_raw(operations, &invalid_utf8, 400)?;
    let mut oversized_header = vec![b'x'; 8 * 1024];
    oversized_header[..27].copy_from_slice(b"GET /health/live HTTP/1.1\r\n");
    assert_status_raw(operations, &oversized_header, 431)?;
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("ingest secret missing")?
    );
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &authorization),
                ("Content-Type", "application/x-protobuf"),
            ],
            &[0xff],
        )?,
        400,
    );
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", "Bearer invalid"),
                ("Content-Type", "application/x-protobuf"),
            ],
            &[0xff],
        )?,
        401,
    );
    assert_status_raw(operations, b"GET /health/live HTTP/1.1\r\n", 400)?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_serves_an_authenticated_administration_request()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-api")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let host = NativeHost::new(
        bindings(&roots, "tls-api")?
            .with_api_transport(ApiTransportProfile::tls(certificate.clone(), private_key)?)?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let response = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::Tls {
            endpoint: api,
            server_name: "localhost".to_owned(),
            trust_file: certificate,
        },
    )?
    .manage(
        claim.secret(),
        &positron_api::api_keys::ApiKeyRequest::list(),
    )?;
    assert_eq!(response.keys.len(), 3);
    let wrong_dial_address =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), api.port()));
    let wrong_dial = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::Tls {
            endpoint: wrong_dial_address,
            server_name: "localhost".to_owned(),
            trust_file: PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/native_transport/fixtures/api-test-cert.pem"
            )),
        },
    )?
    .manage(
        claim.secret(),
        &positron_api::api_keys::ApiKeyRequest::list(),
    );
    assert!(
        wrong_dial.is_err(),
        "the client must use the configured dial address"
    );
    let hostname_mismatch = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::Tls {
            endpoint: api,
            server_name: "not-localhost".to_owned(),
            trust_file: PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/native_transport/fixtures/api-test-cert.pem"
            )),
        },
    )?
    .manage(
        claim.secret(),
        &positron_api::api_keys::ApiKeyRequest::list(),
    );
    assert!(hostname_mismatch.is_err());
    let invalid_trust = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::Tls {
            endpoint: api,
            server_name: "localhost".to_owned(),
            trust_file: PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/native_transport/fixtures/api-test-key.pem"
            )),
        },
    )?
    .manage(
        claim.secret(),
        &positron_api::api_keys::ApiKeyRequest::list(),
    );
    assert!(invalid_trust.is_err());
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}
