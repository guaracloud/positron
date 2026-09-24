use super::*;
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceResponse, logs_service_client::LogsServiceClient,
};
use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_runtime::{TlsFailure, TlsIdentity, TlsProfile, TlsTrust, TransportProfile};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Instant;
use tonic::Request;
use tonic::client::Grpc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/tests/native_transport/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn tls_http_with_client_identity(
    address: SocketAddr,
    trust_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
    method: &str,
    path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(trust_file)? {
        roots.add(certificate?)?;
    }
    let certificates =
        CertificateDer::pem_file_iter(certificate_file)?.collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_file(private_key_file)?;
    let configuration = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)?;
    let connection = ClientConnection::new(
        Arc::new(configuration),
        ServerName::try_from("localhost".to_owned())?,
    )?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut stream = StreamOwned::new(connection, stream);
    let request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    match stream.read_to_string(&mut response) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && !response.is_empty() => {
        },
        Err(error) => return Err(error.into()),
    }
    Ok(response)
}

struct OtlpLogCodec;

struct OtlpLogDecoder;

impl Decoder for OtlpLogDecoder {
    type Item = ExportLogsServiceResponse;
    type Error = tonic::Status;

    fn decode(&mut self, source: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        ExportLogsServiceResponse::decode(source)
            .map(Some)
            .map_err(|error| tonic::Status::internal(error.to_string()))
    }
}

struct OtlpLogEncoder;

impl Encoder for OtlpLogEncoder {
    type Item = ExportLogsServiceRequest;
    type Error = tonic::Status;

    fn encode(&mut self, item: Self::Item, target: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(target)
            .map_err(|error| tonic::Status::internal(error.to_string()))
    }
}

impl Codec for OtlpLogCodec {
    type Encode = ExportLogsServiceRequest;
    type Decode = ExportLogsServiceResponse;
    type Encoder = OtlpLogEncoder;
    type Decoder = OtlpLogDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        OtlpLogEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        OtlpLogDecoder
    }
}

#[test]
fn role_neutral_tls_profile_loads_identity_and_classifies_material_failures() {
    let certificate = fixture("api-test-cert.pem");
    let private_key = fixture("api-test-key.pem");

    let tls = TlsProfile::new(
        TlsIdentity::new(certificate.clone(), private_key.clone()),
        None,
    );
    assert!(tls.load().is_ok());

    let missing_certificate = TlsProfile::new(
        TlsIdentity::new(
            PathBuf::from("/tmp/positron-missing-certificate.pem"),
            private_key,
        ),
        None,
    );
    assert!(matches!(
        missing_certificate.load(),
        Err(TlsFailure::CertificateUnreadable)
    ));

    let invalid_key = TlsProfile::new(
        TlsIdentity::new(certificate.clone(), certificate.clone()),
        None,
    );
    assert!(matches!(
        invalid_key.load(),
        Err(TlsFailure::PrivateKeyInvalid)
    ));

    let invalid_trust = TlsProfile::new(
        TlsIdentity::new(certificate, fixture("api-test-key.pem")),
        Some(TlsTrust::new(fixture("api-test-key.pem"))),
    );
    assert!(matches!(
        invalid_trust.load(),
        Err(TlsFailure::TrustInvalid)
    ));
}

#[test]
fn mtls_profile_requires_a_trusted_client_certificate() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("mtls-peer-validation")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let certificate = fixture("mtls-server-cert.pem");
    let authority = fixture("mtls-ca-cert.pem");
    let profile = TlsProfile::new(
        TlsIdentity::new(certificate.clone(), fixture("mtls-server-key.pem")),
        Some(TlsTrust::new(authority.clone())),
    );
    assert!(profile.load().is_ok());
    let host = NativeHost::new(
        bindings(&roots, "mtls-peer-validation")?
            .with_api_transport(TransportProfile::Tls(profile))?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let response = tls_http(api, &authority, "GET", "/health/live", &[], &[]);
    assert!(
        match response {
            Ok(response) => !response.starts_with("HTTP/1.1 200 "),
            Err(_) => true,
        },
        "a peer without a client certificate must not use the mTLS listener"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn mtls_profile_accepts_only_a_client_trusted_by_its_configured_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("mtls-trusted-client")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let authority = fixture("mtls-ca-cert.pem");
    let transport = TransportProfile::Tls(TlsProfile::new(
        TlsIdentity::new(
            fixture("mtls-server-cert.pem"),
            fixture("mtls-server-key.pem"),
        ),
        Some(TlsTrust::new(authority.clone())),
    ));
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new_with_listener_transports(
        roots.parent.join("mtls-trusted-client.sock"),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
        TransportProfile::plaintext_opt_out(),
        transport,
        TransportProfile::plaintext_opt_out(),
        TransportProfile::plaintext_opt_out(),
        TransportProfile::plaintext_opt_out(),
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::Api,
    )?;
    let trusted = tls_http_with_client_identity(
        api,
        &authority,
        &fixture("mtls-client-cert.pem"),
        &fixture("mtls-client-key.pem"),
        "GET",
        "/v1/capabilities:negotiate",
    )?;
    assert_status(trusted, 405);
    let untrusted = tls_http_with_client_identity(
        api,
        &authority,
        &fixture("api-test-cert.pem"),
        &fixture("api-test-key.pem"),
        "GET",
        "/v1/capabilities:negotiate",
    );
    assert!(
        match untrusted {
            Ok(response) => !response.starts_with("HTTP/1.1 405 "),
            Err(_) => true,
        },
        "an untrusted client certificate must not reach the API route"
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn role_specific_tls_profiles_serve_operations_api_otlp_http_and_loki()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("role-specific-tls")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let certificate = fixture("api-test-cert.pem");
    let transport = TransportProfile::Tls(TlsProfile::new(
        TlsIdentity::new(certificate.clone(), fixture("api-test-key.pem")),
        None,
    ));
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new_with_listener_transports(
        roots.parent.join("role-specific-tls.sock"),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
        transport.clone(),
        transport.clone(),
        transport.clone(),
        transport.clone(),
        transport,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let operations = address(&endpoints, positron_runtime::ListenerRole::Operations)?;
    let api = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let otlp = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;
    let loki = address(&endpoints, positron_runtime::ListenerRole::LokiPush)?;

    assert_status(
        tls_http(operations, &certificate, "GET", "/health/live", &[], &[])?,
        200,
    );
    assert_status(
        tls_http(
            api,
            &certificate,
            "POST",
            "/v1/capabilities:negotiate",
            &[],
            br#"{"api_major":1,"capability":1}"#,
        )?,
        200,
    );
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("ingest secret missing")?
    );
    assert_status(
        tls_http(
            otlp,
            &certificate,
            "POST",
            "/v1/logs",
            &[
                ("Authorization", &authorization),
                ("Content-Type", "application/x-protobuf"),
            ],
            &otlp_body("role-specific-tls"),
        )?,
        200,
    );
    assert_status(
        tls_http(
            loki,
            &certificate,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", &authorization),
                ("Content-Type", "application/json"),
            ],
            br#"{"streams":[]}"#,
        )?,
        204,
    );
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_specific_tls_profile_gracefully_drains_a_retained_idle_otlp_grpc_channel()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("role-specific-grpc-tls")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let certificate = fixture("api-test-cert.pem");
    let transport = TransportProfile::Tls(TlsProfile::new(
        TlsIdentity::new(certificate.clone(), fixture("api-test-key.pem")),
        None,
    ));
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new_with_listener_transports(
        roots.parent.join("role-specific-grpc-tls.sock"),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
        transport.clone(),
        transport.clone(),
        transport.clone(),
        transport.clone(),
        transport,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::OtlpGrpc,
    )?;
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(std::fs::read(&certificate)?));
    let channel = Endpoint::from_shared(format!("https://localhost:{}/", endpoint.port()))?
        .tls_config(tls)?
        .connect()
        .await?;
    let mut client = LogsServiceClient::new(channel.clone());
    let mut request = Request::new(ExportLogsServiceRequest::default());
    request.metadata_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            claim.ingest_secret().ok_or("ingest secret missing")?
        )
        .parse()?,
    );
    assert!(
        client
            .export(request)
            .await?
            .into_inner()
            .partial_success
            .is_none()
    );
    drop(client);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    drop(channel);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn tls_grpc_forces_shutdown_when_an_authenticated_request_exceeds_the_drain_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("role-specific-grpc-tls-forced")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let certificate = fixture("api-test-cert.pem");
    let transport = TransportProfile::Tls(TlsProfile::new(
        TlsIdentity::new(certificate.clone(), fixture("api-test-key.pem")),
        None,
    ));
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let host = NativeHost::new(NativeBindings::new_with_listener_transports(
        roots.parent.join("role-specific-grpc-tls-forced.sock"),
        loopback,
        loopback,
        loopback,
        loopback,
        loopback,
        transport.clone(),
        transport.clone(),
        transport.clone(),
        transport.clone(),
        transport,
    )?);
    let configuration = Arc::new(resolve(ConfigurationInputs::try_new(
        Some("schema_version = 1\n[runtime]\nshutdown_grace_seconds = 1\n"),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
            .with_effective_configuration(configuration),
        HostInputs::new(&host, &host),
    )?;
    let endpoint = address(
        &process.bound_endpoints(),
        positron_runtime::ListenerRole::OtlpGrpc,
    )?;
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(std::fs::read(&certificate)?));
    let channel = Endpoint::from_shared(format!("https://localhost:{}/", endpoint.port()))?
        .tls_config(tls)?
        .connect()
        .await?;
    let mut client = LogsServiceClient::new(channel.clone());
    let mut request = Request::new(ExportLogsServiceRequest::default());
    request.metadata_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            claim.ingest_secret().ok_or("ingest secret missing")?
        )
        .parse()?,
    );
    assert!(
        client
            .export(request)
            .await?
            .into_inner()
            .partial_success
            .is_none()
    );
    drop(client);
    let mut request = Request::new(tokio_stream::pending::<ExportLogsServiceRequest>());
    request.metadata_mut().insert(
        "authorization",
        format!(
            "Bearer {}",
            claim.ingest_secret().ok_or("ingest secret missing")?
        )
        .parse()?,
    );
    let stalled_channel = channel.clone();
    let stalled = tokio::spawn(async move {
        Grpc::new(stalled_channel)
            .streaming(
                request,
                PathAndQuery::from_static(
                    "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
                ),
                OtlpLogCodec,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    let shutdown_started = Instant::now();
    let outcome = process.shutdown(ShutdownTrigger::FirstSignal);
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(2),
        "stalled request exceeded its configured one-second drain budget"
    );
    assert_eq!(outcome, positron_runtime::ExitOutcome::Forced);
    stalled.abort();
    drop(stalled.await);
    drop(channel);
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
