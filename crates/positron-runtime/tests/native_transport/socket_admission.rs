//! Socket-admission outcomes observed through real listener connections.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream as StdTcpStream};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ListenerRole,
    NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tonic::{Code, Request};

use super::support::{
    TestRoots, address, assert_status, http, live_async_test_guard, live_test_guard, tls_http,
};

#[tokio::test(flavor = "current_thread")]
async fn api_global_accepted_socket_cap_closes_another_peer_then_releases_after_the_holder_drops()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("api-global-socket-admission")?;
    let effective =
        effective_configuration(&listener_document(&roots, "plaintext", 1, 1, 128, 16))?;
    let paths = roots.paths()?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(Arc::clone(&effective)),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;

    let mut holder = connect_from(Ipv4Addr::LOCALHOST, api).await?;
    holder
        .write_all(b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\n")
        .await?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    let rejected = connect_from(Ipv4Addr::LOCALHOST, api).await?;
    assert_closed(rejected).await?;

    drop(holder);
    let accepted = request_from(Ipv4Addr::LOCALHOST, api).await?;
    assert_status(accepted, 405);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn api_per_address_accepted_socket_cap_closes_the_second_socket_from_one_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("api-peer-socket-admission")?;
    let effective =
        effective_configuration(&listener_document(&roots, "plaintext", 2, 1, 128, 16))?;
    let paths = roots.paths()?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(effective),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;
    let mut holder = connect_from(Ipv4Addr::LOCALHOST, api).await?;
    holder
        .write_all(b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\n")
        .await?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert_closed(connect_from(Ipv4Addr::LOCALHOST, api).await?).await?;
    drop(holder);
    assert_status(request_from(Ipv4Addr::LOCALHOST, api).await?, 405);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failed_api_tls_handshake_releases_its_accepted_socket_permit()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("api-tls-failed-handshake-admission")?;
    let effective = effective_configuration(&listener_document(&roots, "tls", 1, 1, 128, 16))?;
    let paths = roots.paths()?;
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(effective),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;

    let mut invalid_tls = connect_from(Ipv4Addr::LOCALHOST, api).await?;
    match invalid_tls.write_all(b"not a TLS client hello").await {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(error) => return Err(error.into()),
    }
    drop(invalid_tls);

    let certificate = fixture("api-test-cert.pem");
    let accepted = wait_for_tls_response(api, &certificate)?;
    assert_status(accepted, 405);
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn old_api_generation_keeps_its_lease_until_the_held_socket_releases_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("api-generation-lease-admission")?;
    let initial = effective_configuration(&listener_document(&roots, "plaintext", 1, 1, 128, 16))?;
    let paths = roots.paths()?;
    let host = NativeHost::new(NativeBindings::from_effective(&initial)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty)
            .with_effective_configuration(Arc::clone(&initial)),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;
    let mut holder = StdTcpStream::connect_timeout(&api, Duration::from_secs(2))?;
    holder.write_all(b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\n")?;
    std::thread::sleep(Duration::from_millis(25));
    let successor =
        effective_configuration(&listener_document(&roots, "plaintext", 2, 1, 128, 16))?;

    let (successor_ready, successor_observed) = mpsc::sync_channel(1);
    let probe = std::thread::spawn(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match http(api, "GET", "/v1/capabilities:negotiate", &[], &[]) {
                    Ok(response) if response.starts_with("HTTP/1.1 405 ") => {
                        successor_ready
                            .send(())
                            .map_err(|_| "reload observer dropped")?;
                        drop(holder);
                        return Ok(());
                    },
                    Ok(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    },
                    Ok(response) => {
                        return Err(format!("unexpected successor response: {response}").into());
                    },
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    },
                    Err(error) => return Err(error.to_string().into()),
                }
            }
        },
    );
    let started = Instant::now();
    let outcome = process.reload_configuration(successor)?;
    successor_observed.recv_timeout(Duration::from_millis(250))?;
    assert!(started.elapsed() < Duration::from_secs(1));
    probe
        .join()
        .map_err(|_| "reload observer panicked")?
        .map_err(|error| error.to_string())?;
    assert!(matches!(
        outcome,
        positron_runtime::ConfigurationReloadOutcome::PublishedLive { .. }
    ));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn otlp_grpc_global_accepted_socket_cap_closes_then_releases_for_a_real_rpc()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("grpc-global-socket-admission")?;
    let effective =
        effective_configuration(&listener_document(&roots, "plaintext", 128, 16, 1, 1))?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
            .with_effective_configuration(effective),
        HostInputs::new(&host, &host),
    )?;
    let grpc = address(&process.bound_endpoints(), ListenerRole::OtlpGrpc)?;
    let holder = connect_from(Ipv4Addr::LOCALHOST, grpc).await?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert_closed(connect_from(Ipv4Addr::LOCALHOST, grpc).await?).await?;
    drop(holder);
    let mut client = tokio::time::timeout(
        Duration::from_secs(2),
        LogsServiceClient::connect(format!("http://{grpc}")),
    )
    .await??;
    let refusal = client
        .export(Request::new(ExportLogsServiceRequest::default()))
        .await
        .expect_err("the released permit must expose the OTLP receiver");
    assert_eq!(refusal.code(), Code::Unauthenticated);
    drop(client);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

async fn connect_from(source: Ipv4Addr, endpoint: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::V4(SocketAddrV4::new(source, 0)))?;
    socket.connect(endpoint).await
}

async fn assert_closed(mut stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await? {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        Ok(read) => Err(format!("admission-refused socket produced {read} response bytes").into()),
        Err(error) => Err(error.into()),
    }
}

async fn request_from(
    source: Ipv4Addr,
    endpoint: SocketAddr,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = connect_from(source, endpoint).await?;
    stream
        .write_all(b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
    Ok(String::from_utf8(response)?)
}

fn effective_configuration(
    document: &str,
) -> Result<Arc<positron_config::EffectiveConfiguration>, Box<dyn std::error::Error>> {
    let inputs = ConfigurationInputs::try_new(
        Some(document),
        EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
    )?;
    Ok(Arc::new(resolve(inputs)?))
}

fn listener_document(
    roots: &TestRoots,
    api_transport: &str,
    api_global_limit: u16,
    api_peer_limit: u16,
    grpc_global_limit: u16,
    grpc_peer_limit: u16,
) -> String {
    let api_tls = if api_transport == "tls" {
        let certificate = fixture("api-test-cert.pem");
        let key = fixture("api-test-key.pem");
        format!(
            "api_tls_certificate_file = \"{}\"\napi_tls_private_key_file = \"{}\"\n",
            certificate.display(),
            key.display(),
        )
    } else {
        String::new()
    };
    format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_bind_address = \"127.0.0.1:0\"\napi_transport = \"{api_transport}\"\napi_accepted_socket_limit = {api_global_limit}\napi_per_address_accepted_socket_limit = {api_peer_limit}\n{api_tls}otlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_grpc_transport = \"plaintext\"\notlp_grpc_accepted_socket_limit = {grpc_global_limit}\notlp_grpc_per_address_accepted_socket_limit = {grpc_peer_limit}\notlp_http_bind_address = \"127.0.0.1:0\"\notlp_http_transport = \"plaintext\"\nloki_push_bind_address = \"127.0.0.1:0\"\nloki_push_transport = \"plaintext\"\n",
        roots.parent.join("control.sock").display(),
    )
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "{}/tests/native_transport/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

fn wait_for_tls_response(
    endpoint: SocketAddr,
    certificate: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match tls_http(
            endpoint,
            certificate,
            "GET",
            "/v1/capabilities:negotiate",
            &[],
            &[],
        ) {
            Ok(response) => return Ok(response),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(error),
        }
    }
}
