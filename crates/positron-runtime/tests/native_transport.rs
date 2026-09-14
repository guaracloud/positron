//! Real loopback transport integration tests.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_domain::identity::TenantSlug;
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::MountQualification;
use positron_query::QueryBudget;
use positron_runtime::{
    ApiTransportProfile, ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
    TrustedProxy,
};
use prost::Message;

#[path = "native_transport/support.rs"]
mod support;
use support::*;

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
            .with_public_plaintext_api_warning(),
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

#[test]
fn api_client_manages_a_tenant_bound_key_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-key-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("client-key-tenant")?,
                "Client key tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x89; 16])?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?
        .tenant_id();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-key-client")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let client = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::PlaintextOptOut { endpoint: api },
    )?;
    let target = positron_api::api_keys::ApiKeyRequest::create_for_tenant(
        positron_api::api_keys::KeyScope::Ingest,
        tenant.to_canonical_text(),
        None,
        1,
        "88888888-8888-8888-8888-88888888888a".to_owned(),
    );
    let mut created = client
        .manage(claim.secret(), &target)
        .map_err(|failure| format!("target create: {failure:?}"))?;
    let principal = created.principal.clone().ok_or("created principal")?;
    let secret = created.secret.take().ok_or("one-time tenant secret")?;
    let replay = client
        .manage(claim.secret(), &target)
        .map_err(|failure| format!("target replay: {failure:?}"))?;
    assert_eq!(replay.principal.as_deref(), Some(principal.as_str()));
    assert!(
        replay.secret.is_none(),
        "replay must never redisplay a secret"
    );
    assert!(
        client
            .manage(
                claim.secret(),
                &positron_api::api_keys::ApiKeyRequest::create_for_tenant(
                    positron_api::api_keys::KeyScope::Query,
                    "99999999-9999-9999-9999-999999999999".to_owned(),
                    None,
                    1,
                    "99999999-9999-9999-9999-99999999999a".to_owned(),
                ),
            )
            .is_err(),
        "an unknown tenant must not create an orphan credential"
    );
    let default_created = client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::create(
                positron_api::api_keys::KeyScope::TenantAdministration,
                None,
                1,
                "88888888-8888-8888-8888-88888888888b".to_owned(),
            ),
        )
        .map_err(|failure| format!("legacy default create: {failure:?}"))?;
    assert!(
        default_created.secret.is_some(),
        "omitting target_tenant retains the default credential lifecycle"
    );
    let replay_after_unrelated_mutation = client
        .manage(claim.secret(), &target)
        .map_err(|failure| format!("target replay after mutation: {failure:?}"))?;
    assert_eq!(
        replay_after_unrelated_mutation.principal.as_deref(),
        Some(principal.as_str())
    );
    assert!(
        replay_after_unrelated_mutation.secret.is_none(),
        "an exact retry after unrelated mutation must not redisplay the tenant secret"
    );
    let listed = client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::list_for_tenant(tenant.to_canonical_text()),
        )
        .map_err(|failure| format!("target list: {failure:?}"))?;
    assert_eq!(listed.keys.len(), 1);
    assert_eq!(listed.keys[0].principal, principal);
    assert!(listed.keys[0].active);
    assert_eq!(listed.keys[0].generation, 2);
    let rotation = positron_api::api_keys::ApiKeyRequest::mutation_for_tenant(
        positron_api::api_keys::KeyAction::Rotate,
        principal.clone(),
        tenant.to_canonical_text(),
        2,
        "88888888-8888-8888-8888-88888888888c".to_owned(),
    )?;
    let mut rotated = client
        .manage(claim.secret(), &rotation)
        .map_err(|failure| format!("target rotate: {failure:?}"))?;
    let successor = rotated.principal.clone().ok_or("rotated principal")?;
    let successor_secret = rotated.secret.take().ok_or("rotated secret")?;
    let rotation_replay = client
        .manage(claim.secret(), &rotation)
        .map_err(|failure| format!("target rotation replay: {failure:?}"))?;
    assert_eq!(
        rotation_replay.principal.as_deref(),
        Some(successor.as_str())
    );
    assert!(rotation_replay.secret.is_none());
    client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::mutation_for_tenant(
                positron_api::api_keys::KeyAction::Revoke,
                principal.clone(),
                tenant.to_canonical_text(),
                3,
                "88888888-8888-8888-8888-88888888888d".to_owned(),
            )?,
        )
        .map_err(|failure| format!("target revoke: {failure:?}"))?;
    let after_revoke = client
        .manage(
            claim.secret(),
            &positron_api::api_keys::ApiKeyRequest::list_for_tenant(tenant.to_canonical_text()),
        )
        .map_err(|failure| format!("target list after revoke: {failure:?}"))?;
    assert_eq!(after_revoke.keys.len(), 2);
    assert!(
        after_revoke
            .keys
            .iter()
            .any(|key| { key.principal == principal && !key.active && key.generation == 4 })
    );
    assert!(
        after_revoke
            .keys
            .iter()
            .any(|key| { key.principal == successor && key.active && key.generation == 4 })
    );
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::OtlpHttp,
            )?,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &format!("Bearer {secret}")),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("tenant-key-revoked"),
        )?,
        401,
    );
    assert_status(
        http(
            address(
                &process.bound_endpoints(),
                positron_runtime::ListenerRole::OtlpHttp,
            )?,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &format!("Bearer {successor_secret}")),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("tenant-key-client"),
        )?,
        200,
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn tenant_quota_client_updates_a_bound_tenant_with_replay_and_redacted_stale_details()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-quota-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("client-quota-tenant")?,
                "Client quota tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x99; 16])?,
        )?
        .tenant_id();
    let administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x9a; 16])?,
    )?;
    let administrator_secret = administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-quota-client")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let client = positron_api::tenant_quotas::TenantQuotaServiceClient::new(
        positron_api::tenant_quotas::TenantQuotaTransport::PlaintextOptOut { endpoint: api },
    )?;
    let resources = positron_api::tenant_quotas::TenantQuotaResources {
        memory_bytes: 3,
        queue_slots: 3,
        task_slots: 3,
        buffer_cache_bytes: 3,
        batch_items: 3,
        lease_slots: 3,
        retry_slots: 3,
        io_permits: 3,
        cpu_work_units: 3,
        file_descriptors: 3,
        disk_headroom_bytes: 3,
    };
    let request = positron_api::tenant_quotas::TenantQuotaUpdateRequest::new(
        tenant.to_canonical_text(),
        1,
        "98989898-9898-9898-9898-98989898989a".to_owned(),
        1,
        resources,
    );
    let created = client
        .update(&administrator_secret, &request)
        .map_err(|failure| format!("quota update: {failure:?}"))?;
    assert_eq!(created.resource_generation, 2);
    assert_eq!(
        client
            .update(&administrator_secret, &request)
            .map_err(|failure| format!("quota replay: {failure:?}"))?
            .resource_generation,
        2
    );
    assert!(matches!(
        client.update(
            &administrator_secret,
            &positron_api::tenant_quotas::TenantQuotaUpdateRequest::new(
                tenant.to_canonical_text(),
                1,
                "98989898-9898-9898-9898-98989898989a".to_owned(),
                1,
                positron_api::tenant_quotas::TenantQuotaResources {
                    memory_bytes: 4,
                    ..resources
                },
            ),
        ),
        Err(positron_api::tenant_quotas::TenantQuotaServiceClientFailure::IdempotencyConflict)
    ));
    assert!(matches!(
        client.update(
            &administrator_secret,
            &positron_api::tenant_quotas::TenantQuotaUpdateRequest::new(
                tenant.to_canonical_text(),
                1,
                "98989898-9898-9898-9898-98989898989b".to_owned(),
                1,
                positron_api::tenant_quotas::TenantQuotaResources {
                    memory_bytes: 4,
                    ..resources
                },
            ),
        ),
        Err(positron_api::tenant_quotas::TenantQuotaServiceClientFailure::StaleGeneration {
            resource_generation: 2,
            ref semantic_diff,
        }) if semantic_diff == "memory_bytes"
    ));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn tenant_lifecycle_client_transitions_replays_and_redacts_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-lifecycle-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let tenant = initialized.default_tenant_id().to_canonical_text();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-lifecycle-client")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(
        http(
            api,
            "POST",
            positron_api::tenant_lifecycle::HTTP_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"unauthorized bodies stay unread"}"#,
        )?,
        401,
    );
    let client = positron_api::tenant_lifecycle::TenantLifecycleServiceClient::new(
        positron_api::tenant_lifecycle::TenantLifecycleTransport::PlaintextOptOut { endpoint: api },
    )?;
    let read_only = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::ReadOnly,
        1,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned(),
    );
    let first = client.transition(claim.secret(), &read_only)?;
    assert_eq!(
        first.to,
        positron_api::tenant_lifecycle::TenantLifecycleState::ReadOnly
    );
    assert_eq!(first.lifecycle_generation, 2);

    let reopened = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        2,
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_owned(),
    );
    let second = client.transition(claim.secret(), &reopened)?;
    assert_eq!(second.lifecycle_generation, 3);
    assert_eq!(
        client.transition(claim.secret(), &read_only)?,
        first,
        "an exact retry resolves the committed result after a later successor"
    );
    let changed_same_key = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        2,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &changed_same_key),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::IdempotencyConflict
        )
    );

    let stale_same = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        2,
        "cccccccc-cccc-cccc-cccc-cccccccccccc".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &stale_same),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::StaleGeneration {
                lifecycle_generation: 3,
                semantic_diff: "lifecycle generation changed".to_owned(),
            }
        )
    );
    let stale_different = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Suspended,
        2,
        "dddddddd-dddd-dddd-dddd-dddddddddddd".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &stale_different),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::StaleGeneration {
                lifecycle_generation: 3,
                semantic_diff: "lifecycle state changed".to_owned(),
            }
        )
    );
    let invalid = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Active,
        3,
        "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &invalid),
        Err(positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::InvalidTransition)
    );
    let purged = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        tenant.clone(),
        positron_api::tenant_lifecycle::TenantLifecycleState::Purged,
        3,
        "ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &purged),
        Err(
            positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::PurgeCompletionUnavailable
        )
    );
    let unknown = positron_api::tenant_lifecycle::TenantLifecycleTransitionRequest::new(
        "11111111-1111-1111-1111-111111111111".to_owned(),
        positron_api::tenant_lifecycle::TenantLifecycleState::ReadOnly,
        1,
        "12121212-1212-1212-1212-121212121212".to_owned(),
    );
    assert_eq!(
        client.transition(claim.secret(), &unknown),
        Err(positron_api::tenant_lifecycle::TenantLifecycleServiceClientFailure::TenantUnavailable)
    );
    let stale_raw = http(
        api,
        "POST",
        positron_api::tenant_lifecycle::HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {}", claim.secret())),
            ("Content-Type", "application/json"),
        ],
        &stale_same.encode()?,
    )?;
    assert_status(stale_raw.clone(), 409);
    assert!(stale_raw.contains("lifecycle generation changed"));
    assert!(!stale_raw.contains(&tenant));
    assert!(!stale_raw.contains("aaaaaaaa"));
    assert_status(
        http(
            api,
            "POST",
            positron_api::tenant_aliases::HTTP_PATH,
            &[("Content-Type", "application/json")],
            br#"{"tenant":"never-decoded","external_alias":"secret-alias","expected_generation":0,"idempotency_key":"never-decoded"}"#,
        )?,
        401,
    );
    let alias_request = format!(
        "{{\"tenant\":\"{tenant}\",\"external_alias\":\"loki.native-alias\",\"expected_generation\":1,\"idempotency_key\":\"99999999-9999-9999-9999-999999999999\"}}"
    );
    let alias_raw = http(
        api,
        "POST",
        positron_api::tenant_aliases::HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {}", claim.secret())),
            ("Content-Type", "application/json"),
        ],
        alias_request.as_bytes(),
    )?;
    assert_status(alias_raw.clone(), 200);
    assert!(alias_raw.contains("\"alias_generation\":2"));
    assert!(!alias_raw.contains("loki.native-alias"));
    assert!(!alias_raw.contains(claim.secret()));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn system_administrator_manages_explicit_tenants_over_the_public_http_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-svc")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    drop(initialized);
    let host = NativeHost::new(bindings(&roots, "tenant-svc")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let authorization = format!("Bearer {}", claim.secret());
    let creation = r#"{"slug":"public-tenant","display_name":"Public tenant","retention_seconds":2592000,"weight":1,"memory_bytes":32000000,"queue_slots":32,"task_slots":32,"buffer_cache_bytes":5000000,"batch_items":2048,"lease_slots":32,"retry_slots":32,"io_permits":32,"cpu_work_units":32,"file_descriptors":32,"disk_headroom_bytes":2000000,"idempotency_key":"abababab-abab-abab-abab-abababababab"}"#;
    let created = http(
        api,
        "POST",
        positron_api::tenant_service::CREATE_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        creation.as_bytes(),
    )?;
    assert_status(created.clone(), 200);
    assert!(created.contains("\"resource_generation\":2"), "{created}");
    let created_body = created
        .split_once("\r\n\r\n")
        .ok_or("tenant create response body")?
        .1;
    let tenant =
        positron_api::tenant_service::TenantCreateResponse::decode(created_body.as_bytes())?.tenant;
    let replay = http(
        api,
        "POST",
        positron_api::tenant_service::CREATE_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        creation.as_bytes(),
    )?;
    assert_status(replay.clone(), 200);
    let replay_body = replay
        .split_once("\r\n\r\n")
        .ok_or("tenant create replay response body")?
        .1;
    assert_eq!(
        positron_api::tenant_service::TenantCreateResponse::decode(replay_body.as_bytes())?.tenant,
        tenant
    );
    let inspection = http(
        api,
        "POST",
        positron_api::tenant_service::INSPECT_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        format!(r#"{{"tenant":"{tenant}"}}"#).as_bytes(),
    )?;
    assert_status(inspection.clone(), 200);
    assert!(inspection.contains("\"slug\":\"public-tenant\""));
    assert!(!inspection.contains("secret"));
    let listed = http(
        api,
        "POST",
        positron_api::tenant_service::LIST_HTTP_PATH,
        &[
            ("Authorization", &authorization),
            ("Content-Type", "application/json"),
        ],
        br#"{}"#,
    )?;
    assert_status(listed.clone(), 200);
    assert!(listed.contains(&tenant));
    let renamed = http(
        api,
        "POST",
        positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH,
        &[("Authorization", &authorization), ("Content-Type", "application/json")],
        format!(r#"{{"tenant":"{tenant}","expected_display_generation":1,"display_name":"Renamed public tenant","idempotency_key":"acacacac-acac-acac-acac-acacacacacac"}}"#).as_bytes(),
    )?;
    assert_status(renamed.clone(), 200);
    assert!(renamed.contains("\"display_generation\":2"));
    let stale = http(
        api,
        "POST",
        positron_api::tenant_service::UPDATE_DISPLAY_NAME_HTTP_PATH,
        &[("Authorization", &authorization), ("Content-Type", "application/json")],
        format!(r#"{{"tenant":"{tenant}","expected_display_generation":1,"display_name":"Another label","idempotency_key":"adadadad-adad-adad-adad-adadadadadad"}}"#).as_bytes(),
    )?;
    assert_status(stale.clone(), 409);
    assert!(stale.contains("\"display_generation\":2"));
    assert!(stale.contains("\"semantic_diff\":\"display_name\""));
    let malformed = http(
        api,
        "POST",
        positron_api::tenant_service::CREATE_HTTP_PATH,
        &[
            ("Authorization", "Bearer invalid"),
            ("Content-Type", "application/json"),
        ],
        br#"{"malformed":true}"#,
    )?;
    assert_status(malformed, 401);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn tenant_policy_preview_is_authorized_before_decode_and_never_activates()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tenant-policy-preview")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("client-policy-tenant")?,
                "Client policy tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x9c; 16])?,
        )?
        .tenant_id();
    let administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x9d; 16])?,
    )?;
    let administrator_secret = administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    drop(initialized);

    let host = NativeHost::new(bindings(&roots, "tenant-policy-preview")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_VALIDATE_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"the policy body must remain unread"}"#,
        )?,
        401,
    );
    let client = positron_api::policy::PolicyPreviewServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    let request = positron_api::policy::PolicyPreviewRequest::new(
        r#"{"generation":17,"rules":[]}"#.to_owned(),
    );
    assert_eq!(
        client.validate(claim.secret(), &request),
        Err(positron_api::policy::PolicyPreviewServiceClientFailure::AuthenticationRejected)
    );
    let preview = client.validate(&administrator_secret, &request)?;
    assert_eq!(preview.policy_generation, 17);
    assert_eq!(preview.rule_count, 0);
    assert_eq!(
        client.validate(&administrator_secret, &request)?,
        preview,
        "non-mutating validation must not activate the prospective candidate"
    );
    let policy_test_body = br#"{"policy_json":"{\"generation\":18,\"rules\":[{\"id\":\"reject-secret\",\"predicates\":[{\"body_exact_text\":\"secret-canary\"}],\"action\":\"reject\"}]}","candidate_json":"{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"body\":\"secret-canary\",\"attributes\":[]}"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_TEST_PATH,
            &[
                ("Authorization", &format!("Bearer {}", claim.secret())),
                ("Content-Type", "application/json"),
            ],
            br#"{"unknown":"candidate body must remain unread"}"#,
        )?,
        401,
    );
    let test_client = positron_api::policy::PolicyTestServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    assert_eq!(
        test_client.test(
            claim.secret(),
            &positron_api::policy::PolicyTestRequest::new(
                "{\"generation\":18,\"rules\":[]}".to_owned(),
                "{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}"
                    .to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyTestServiceClientFailure::AuthenticationRejected)
    );
    let raw = http(
        api,
        "POST",
        positron_api::policy::HTTP_TEST_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        policy_test_body,
    )?;
    assert_status(raw.clone(), 200);
    assert!(raw.contains("\"accepted\":false"));
    assert!(raw.contains("\"applied_rule_count\":1"));
    assert!(!raw.contains("secret-canary"));
    assert!(!raw.contains("reject-secret"));
    let policy_diff_body = br#"{"before_policy_json":"{\"generation\":18,\"rules\":[{\"id\":\"before-secret\",\"predicates\":[{\"body_exact_text\":\"before-canary\"}],\"action\":\"reject\"}]}","after_policy_json":"{\"generation\":19,\"rules\":[{\"id\":\"after-secret\",\"predicates\":[{\"body_exact_text\":\"after-canary\"}],\"action\":\"reject\"}]}"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_DIFF_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"policy bodies must remain unread before authorization"}"#,
        )?,
        401,
    );
    let diff_client = positron_api::policy::PolicyDiffServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    assert_eq!(
        diff_client.diff(
            claim.secret(),
            &positron_api::policy::PolicyDiffRequest::new(
                "{\"generation\":18,\"rules\":[]}".to_owned(),
                "{\"generation\":19,\"rules\":[]}".to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyDiffServiceClientFailure::AuthenticationRejected)
    );
    let raw = http(
        api,
        "POST",
        positron_api::policy::HTTP_DIFF_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        policy_diff_body,
    )?;
    assert_status(raw.clone(), 200);
    assert!(raw.contains("\"generation_changed\""));
    assert!(raw.contains("\"rule_added\""));
    assert!(raw.contains("\"rule_removed\""));
    assert!(!raw.contains("before-secret"));
    assert!(!raw.contains("after-secret"));
    assert!(!raw.contains("before-canary"));
    assert!(!raw.contains("after-canary"));
    assert_eq!(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_DIFF_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            policy_diff_body,
        )?,
        raw,
        "policy diff is prospective and non-mutating"
    );
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_EXPLAIN_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"candidate stays unread before authentication"}"#,
        )?,
        401,
    );
    let raw = http(
        api,
        "POST",
        positron_api::policy::HTTP_EXPLAIN_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        policy_test_body,
    )?;
    assert_status(raw.clone(), 200);
    assert!(raw.contains("\"outcome\":\"rejected\""));
    assert!(raw.contains("matched rule action=reject"));
    assert!(!raw.contains("reject-secret"));
    assert!(!raw.contains("secret-canary"));
    let activate_first = br#"{"policy_json":"{\"generation\":2,\"rules\":[{\"id\":\"reject-first\",\"predicates\":[{\"receiver\":\"otlp_http_json\"}],\"action\":\"reject\"}]}","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[("Content-Type", "application/json")],
            br#"{"unknown":"candidate remains unread before authentication"}"#,
        )?,
        401,
    );
    let activate_client = positron_api::policy::PolicyActivateServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::PlaintextOptOut { endpoint: api },
    )?;
    assert_eq!(
        activate_client.activate(
            claim.secret(),
            &positron_api::policy::PolicyActivateRequest::new(
                "{\"generation\":2,\"rules\":[]}".to_owned(),
                1,
                "01010101-0101-0101-0101-010101010101".to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyActivateServiceClientFailure::AuthenticationRejected)
    );
    let activated = http(
        api,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        activate_first,
    )?;
    assert_status(activated.clone(), 200);
    assert!(activated.contains("\"resource_generation\":2"));
    assert!(activated.contains("\"audit_position\":"));
    assert!(!activated.contains("reject-first"));
    let stale = http(
        api,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","expected_generation":1,"idempotency_key":"02020202-0202-0202-0202-020202020202"}"#,
    )?;
    assert_status(stale.clone(), 409);
    assert!(stale.contains("\"resource_generation\":2"));
    assert!(stale.contains("\"semantic_diff\":\"policy generation changed\""));
    let changed_replay = http(
        api,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#,
    )?;
    assert_status(changed_replay, 409);
    let activate_second = br#"{"policy_json":"{\"generation\":3,\"rules\":[]}","expected_generation":2,"idempotency_key":"03030303-0303-0303-0303-030303030303"}"#;
    assert_status(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            activate_second,
        )?,
        200,
    );
    assert_eq!(
        http(
            api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            activate_first,
        )?,
        activated,
        "an exact activation retry resolves its durable original receipt after a later update"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let reopened_host = NativeHost::new(bindings(&roots, "tenant-policy-preview-reopened")?);
    let reopened = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&reopened_host, &reopened_host),
    )?;
    let reopened_api = address(
        &reopened.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_eq!(
        http(
            reopened_api,
            "POST",
            positron_api::policy::HTTP_ACTIVATE_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            activate_first,
        )?,
        activated,
        "an exact activation retry survives reopen after a later update"
    );
    assert_eq!(
        reopened.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_serves_policy_test_through_the_generated_client()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-policy-test")?;
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
        bindings(&roots, "tls-policy-test")?
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
    let client = positron_api::policy::PolicyTestServiceClient::new(
        positron_api::policy::PolicyPreviewTransport::Tls {
            endpoint: api,
            server_name: "localhost".to_owned(),
            trust_file: certificate,
        },
    )?;
    assert_eq!(
        client.test(
            claim.secret(),
            &positron_api::policy::PolicyTestRequest::new(
                "{\"generation\":23,\"rules\":[]}".to_owned(),
                "{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}"
                    .to_owned(),
            ),
        ),
        Err(positron_api::policy::PolicyTestServiceClientFailure::AuthenticationRejected),
        "the secure Test transport must reach tenant authorization without decoding a system credential as tenant authority"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_reaches_alias_explain_and_activate_before_decoding()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-api-route-parity")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("tls-route-tenant")?,
                "TLS route tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0xE2; 16])?,
        )?
        .tenant_id();
    let tenant_administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xE3; 16])?,
    )?;
    let tenant_administrator_secret = tenant_administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    drop(initialized);

    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let host = NativeHost::new(
        bindings(&roots, "tls-api-route-parity")?
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

    for path in [
        positron_api::tenant_aliases::HTTP_PATH,
        positron_api::policy::HTTP_EXPLAIN_PATH,
        positron_api::policy::HTTP_ACTIVATE_PATH,
    ] {
        assert_status(
            tls_http(
                api,
                &certificate,
                "POST",
                path,
                &[
                    ("Authorization", "Bearer invalid"),
                    ("Content-Type", "application/json"),
                ],
                br#"{"malformed":"body must remain unread"}"#,
            )?,
            401,
        );
    }

    let system_authorization = format!("Bearer {}", claim.secret());
    let alias = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::tenant_aliases::HTTP_PATH,
        &[
            ("Authorization", &system_authorization),
            ("Content-Type", "application/json"),
        ],
        format!(
            r#"{{"tenant":"{}","external_alias":"tls-route-alias","expected_generation":1,"idempotency_key":"e4e4e4e4-e4e4-e4e4-e4e4-e4e4e4e4e4e4"}}"#,
            tenant.to_canonical_text()
        )
        .as_bytes(),
    )?;
    assert_status(alias.clone(), 200);
    assert!(alias.contains("\"alias_generation\":2"));
    assert!(!alias.contains("tls-route-alias"));

    let tenant_authorization = format!("Bearer {tenant_administrator_secret}");
    let explanation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::policy::HTTP_EXPLAIN_PATH,
        &[
            ("Authorization", &tenant_authorization),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","candidate_json":"{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}"}"#,
    )?;
    assert_status(explanation.clone(), 200);
    assert!(explanation.contains("\"outcome\":\"accepted\""));

    let activation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::policy::HTTP_ACTIVATE_PATH,
        &[
            ("Authorization", &tenant_authorization),
            ("Content-Type", "application/json"),
        ],
        br#"{"policy_json":"{\"generation\":2,\"rules\":[]}","expected_generation":1,"idempotency_key":"e5e5e5e5-e5e5-e5e5-e5e5-e5e5e5e5e5e5"}"#,
    )?;
    assert_status(activation.clone(), 200);
    assert!(activation.contains("\"resource_generation\":2"));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn configured_tls_api_listener_serves_tenant_retention_preview_and_confirmed_update()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("tls-tenant-retention")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let other_tenant = initialized.default_tenant_id();
    let tenant = initialized
        .create_tenant_generated(
            system,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("tls-retention-tenant")?,
                "TLS retention tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0xe8; 16])?,
        )?
        .tenant_id();
    let administrator = initialized.create_api_key_for_tenant(
        system,
        tenant,
        positron_domain::identity::Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe9; 16])?,
    )?;
    let administrator_secret = administrator
        .secret()
        .ok_or("tenant administration secret")?
        .to_owned();
    initialized.transition_tenant_lifecycle(
        system,
        tenant,
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xed; 16])?,
    )?;
    drop(initialized);

    let certificate = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-cert.pem"
    ));
    let private_key = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/native_transport/fixtures/api-test-key.pem"
    ));
    let host = NativeHost::new(
        bindings(&roots, "tls-tenant-retention")?.with_api_transport(ApiTransportProfile::tls(
            certificate.clone(),
            private_key.clone(),
        )?)?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    for path in [
        positron_api::tenant_retention::PREVIEW_HTTP_PATH,
        positron_api::tenant_retention::UPDATE_HTTP_PATH,
    ] {
        assert_status(
            tls_http(
                api,
                &certificate,
                "POST",
                path,
                &[
                    ("Authorization", "Bearer invalid"),
                    ("Content-Type", "application/json"),
                ],
                br#"{"malformed":"body must remain unread"}"#,
            )?,
            401,
        );
    }

    let preview_body = format!(
        r#"{{"tenant":"{}","proposed_retention_seconds":86400}}"#,
        tenant.to_canonical_text()
    );
    assert_status(
        tls_http(
            api,
            &certificate,
            "POST",
            positron_api::tenant_retention::PREVIEW_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {}", claim.secret())),
                ("Content-Type", "application/json"),
            ],
            preview_body.as_bytes(),
        )?,
        401,
    );
    assert_status(
        tls_http(
            api,
            &certificate,
            "POST",
            positron_api::tenant_retention::PREVIEW_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            format!(
                r#"{{"tenant":"{}","proposed_retention_seconds":86400}}"#,
                other_tenant.to_canonical_text()
            )
            .as_bytes(),
        )?,
        401,
    );
    let client = positron_api::tenant_retention::TenantRetentionServiceClient::new(
        positron_api::tenant_retention::TenantRetentionTransport::Tls {
            endpoint: api,
            server_name: "localhost".to_owned(),
            trust_file: certificate.clone(),
        },
    )?;
    let preview = client.preview(
        &administrator_secret,
        &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
            tenant.to_canonical_text(),
            86_400,
        ),
    )?;
    assert_eq!(preview.tenant, tenant.to_canonical_text());
    let digest = preview.confirmation_digest;
    let evaluation = preview.confirmation_evaluated_at_unix_nanos;
    let reduction = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        86_400,
        preview.retention_generation,
        Some(digest.clone()),
        "ebebebeb-ebeb-ebeb-ebeb-ebebebebebeb".to_owned(),
    )
    .with_confirmation_evaluated_at_unix_nanos(evaluation);
    let updated = client.update(&administrator_secret, &reduction)?;
    assert_eq!(updated.retention_generation, 2);
    assert_eq!(client.update(&administrator_secret, &reduction)?, updated);
    let stale_confirmation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::tenant_retention::UPDATE_HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        format!(
            r#"{{"tenant":"{}","proposed_retention_seconds":86400,"expected_generation":1,"confirmation_digest":"{digest}","confirmation_evaluated_at_unix_nanos":{evaluation},"idempotency_key":"ecececec-ecec-ecec-ecec-ecececececec"}}"#,
            tenant.to_canonical_text()
        )
        .as_bytes(),
    )?;
    assert_status(stale_confirmation.clone(), 409);
    assert!(stale_confirmation.contains("\"code\":\"invalid_confirmation\""));
    let stale_generation = tls_http(
        api,
        &certificate,
        "POST",
        positron_api::tenant_retention::UPDATE_HTTP_PATH,
        &[
            ("Authorization", &format!("Bearer {administrator_secret}")),
            ("Content-Type", "application/json"),
        ],
        format!(
            r#"{{"tenant":"{}","proposed_retention_seconds":2700000,"expected_generation":1,"idempotency_key":"f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0"}}"#,
            tenant.to_canonical_text()
        )
        .as_bytes(),
    )?;
    assert_status(stale_generation.clone(), 409);
    assert!(stale_generation.contains("\"code\":\"stale_generation\""));
    assert!(stale_generation.contains("\"retention_generation\":2"));
    assert!(stale_generation.contains("\"semantic_diff\":\"retention_seconds\""));
    let expansion_preview = client.preview(
        &administrator_secret,
        &positron_api::tenant_retention::TenantRetentionPreviewRequest::new(
            tenant.to_canonical_text(),
            2_700_000,
        ),
    )?;
    assert_eq!(expansion_preview.retention_generation, 2);
    let expansion = positron_api::tenant_retention::TenantRetentionUpdateRequest::new(
        tenant.to_canonical_text(),
        2_700_000,
        2,
        None,
        "f1f1f1f1-f1f1-f1f1-f1f1-f1f1f1f1f1f1".to_owned(),
    );
    let expanded = client.update(&administrator_secret, &expansion)?;
    assert_eq!(expanded.retention_generation, 3);
    assert_eq!(client.update(&administrator_secret, &expansion)?, expanded);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let system = reopened.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    reopened.transition_tenant_lifecycle(
        system,
        tenant,
        TenantLifecycleState::Suspended,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xee; 16])?,
    )?;
    drop(reopened);
    let suspended_host = NativeHost::new(
        bindings(&roots, "tls-tenant-retention-suspended")?
            .with_api_transport(ApiTransportProfile::tls(certificate.clone(), private_key)?)?,
    );
    let suspended = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&suspended_host, &suspended_host),
    )?;
    let suspended_api = address(
        &suspended.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    assert_status(
        tls_http(
            suspended_api,
            &certificate,
            "POST",
            positron_api::tenant_retention::PREVIEW_HTTP_PATH,
            &[
                ("Authorization", &format!("Bearer {administrator_secret}")),
                ("Content-Type", "application/json"),
            ],
            preview_body.as_bytes(),
        )?,
        401,
    );
    assert_eq!(
        suspended.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

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
