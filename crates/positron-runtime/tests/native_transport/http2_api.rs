//! HTTP/2 outcomes exposed by the native API listener.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use bytes::Bytes;
use h2::client;
use http::Request;
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ListenerRole,
    NativeHost, ServeConfiguration, ShutdownTrigger, TlsIdentity, TlsProfile, TransportProfile,
};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::support::{
    TestRoots, address, assert_status, bindings, http, live_async_test_guard, live_test_guard,
};

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "{}/tests/native_transport/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn plaintext_opt_out_api_serves_existing_route_over_http2()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("api-http2-plaintext")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    drop(InstanceBootstrap::claim(&paths)?);
    let host = NativeHost::new(bindings(&roots, "api-http2-plaintext")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;
    assert_status(
        http(api, "GET", "/v1/capabilities:negotiate", &[], &[])?,
        405,
    );
    let stream = TcpStream::connect(api).await?;
    let (mut client, connection) = client::handshake(stream).await?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/v1/capabilities:negotiate")
        .body(())?;
    let (response, _send) = client.send_request(request, true)?;
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), 405);
    let request = Request::builder()
        .method("POST")
        .uri("http://localhost/v1/capabilities:negotiate")
        .body(())?;
    let (response, mut request_body) = client.send_request(request, false)?;
    request_body.send_data(Bytes::from(vec![b'x'; 65]), true)?;
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), 413);
    drop(client);
    connection.abort();
    let _ = connection.await;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn tls_api_negotiates_http2_alpn_and_serves_existing_route()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let roots = TestRoots::new("api-http2-tls")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    drop(InstanceBootstrap::claim(&paths)?);
    let certificate = fixture("api-test-cert.pem");
    let profile = TlsProfile::new(
        TlsIdentity::new(certificate.clone(), fixture("api-test-key.pem")),
        None,
    );
    let host = NativeHost::new(
        bindings(&roots, "api-http2-tls")?.with_api_transport(TransportProfile::Tls(profile))?,
    );
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;

    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&certificate)? {
        roots.add(certificate?)?;
    }
    let mut configuration = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    configuration.alpn_protocols = vec![b"h2".to_vec()];
    let tls = TlsConnector::from(Arc::new(configuration))
        .connect(
            ServerName::try_from("localhost".to_owned())?,
            TcpStream::connect(api).await?,
        )
        .await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut client, connection) = client::handshake(tls).await?;
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/v1/capabilities:negotiate")
        .body(())?;
    let (response, _send) = client.send_request(request, true)?;
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), 405);
    drop(client);
    connection.abort();
    let _ = connection.await;

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn idle_http2_api_connection_drains_on_graceful_shutdown() -> Result<(), Box<dyn std::error::Error>>
{
    let _guard = live_test_guard();
    let roots = TestRoots::new("api-http2-drain")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    drop(InstanceBootstrap::claim(&paths)?);
    let host = NativeHost::new(bindings(&roots, "api-http2-drain")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;
    let (ready, waiting) = mpsc::sync_channel(1);
    let client = std::thread::spawn(move || -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async move {
            let stream = TcpStream::connect(api)
                .await
                .map_err(|error| error.to_string())?;
            let (mut client, connection) = client::handshake(stream)
                .await
                .map_err(|error| error.to_string())?;
            let connection = tokio::spawn(connection);
            let request = Request::builder()
                .method("GET")
                .uri("http://localhost/v1/capabilities:negotiate")
                .body(())
                .map_err(|error| error.to_string())?;
            let (response, _send) = client
                .send_request(request, true)
                .map_err(|error| error.to_string())?;
            let response = tokio::time::timeout(Duration::from_secs(2), response)
                .await
                .map_err(|_| "HTTP/2 response timed out".to_owned())?
                .map_err(|error| error.to_string())?;
            if response.status() != 405 {
                return Err(format!(
                    "unexpected HTTP/2 response status: {}",
                    response.status()
                ));
            }
            ready
                .send(())
                .map_err(|_| "shutdown coordinator disconnected".to_owned())?;
            tokio::time::timeout(Duration::from_secs(2), connection)
                .await
                .map_err(|_| "HTTP/2 connection did not close during drain".to_owned())?
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())
        })
    });
    waiting.recv_timeout(Duration::from_secs(2))?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    client
        .join()
        .map_err(|_| std::io::Error::other("HTTP/2 client thread panicked"))?
        .map_err(std::io::Error::other)?;
    Ok(())
}
