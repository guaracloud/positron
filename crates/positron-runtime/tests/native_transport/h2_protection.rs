//! HTTP/2 abuse bounds observed through the OTLP gRPC listener.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::client;
use http::Request;
use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ListenerRole,
    NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::support::{TestRoots, address, live_async_test_guard, otlp_body};

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

#[tokio::test(flavor = "current_thread")]
async fn grpc_body_deadline_releases_the_single_stream_for_a_following_export()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let mut harness = GrpcHarness::start("grpc-body-deadline", "plaintext", 1, 5)?;
    let stream = TcpStream::connect(harness.endpoint).await?;
    let (mut sender, connection) = client::handshake(stream).await?;
    let connection = tokio::spawn(connection);

    let (response, mut body) = sender.send_request(harness.request()?, false)?;
    body.send_data(Bytes::from_static(&[0, 0]), false)?;
    let started = tokio::time::Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_body_deadline(response).await?;
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "the request ended before the configured body deadline: {:?}",
        started.elapsed()
    );
    drop(body);
    drop(sender);
    connection.abort();
    let _ = connection.await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    fresh_authenticated_export(&harness).await?;
    harness.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_hostile_second_stream_is_refused_after_the_one_stream_setting()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let mut harness = GrpcHarness::start("grpc-hostile-stream-cap", "plaintext", 1, 3)?;
    let mut stream = TcpStream::connect(harness.endpoint).await?;
    stream.write_all(H2_PREFACE).await?;
    write_frame(&mut stream, 4, 0, 0, &[]).await?;
    let settings = next_frame(&mut stream).await?;
    assert_eq!(settings.kind, 4);
    assert_eq!(settings.flags, 0);
    assert!(
        settings
            .payload
            .chunks_exact(6)
            .any(|setting| setting == [0, 3, 0, 0, 0, 1]),
        "server did not advertise the configured one-stream HTTP/2 limit"
    );
    write_frame(&mut stream, 4, 1, 0, &[]).await?;

    let headers = grpc_headers(&harness.bearer);
    write_frame(&mut stream, 1, 4, 1, &headers).await?;
    write_frame(&mut stream, 0, 0, 1, &[0, 0]).await?;
    assert_first_stream_has_not_been_refused(&mut stream).await?;
    write_frame(&mut stream, 1, 5, 3, &headers).await?;
    stream.flush().await?;

    let refusal = tokio::time::timeout(Duration::from_secs(2), next_frame(&mut stream)).await??;
    assert_eq!(refusal.kind, 3);
    assert_eq!(refusal.stream, 3);
    assert_eq!(refusal.payload, [0, 0, 0, 7]);
    drop(stream);
    fresh_authenticated_export(&harness).await?;
    harness.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_fragmented_header_block_expires_absolutely_and_releases_connection_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let mut harness = GrpcHarness::start("grpc-header-deadline", "plaintext", 1, 3)?;
    let mut stream = TcpStream::connect(harness.endpoint).await?;
    stream.write_all(H2_PREFACE).await?;
    stream.write_all(&frame(0, 4, 0, 0)).await?;
    stream.write_all(&frame(1, 1, 0, 1)).await?;
    stream.write_all(&[0x82]).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    stream.write_all(&frame(1, 9, 0, 1)).await?;
    stream.write_all(&[0x86]).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_closed(stream).await?;

    assert_unauthenticated(TcpStream::connect(harness.endpoint).await?).await?;
    harness.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_trickled_initial_preface_expires_absolutely_and_releases_connection_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    for transport in ["plaintext", "tls"] {
        let mut harness = GrpcHarness::start(
            &format!("grpc-preface-deadline-{transport}"),
            transport,
            1,
            3,
        )?;
        if transport == "plaintext" {
            trickle_initial_preface(TcpStream::connect(harness.endpoint).await?).await?;
            assert_unauthenticated(TcpStream::connect(harness.endpoint).await?).await?;
        } else {
            trickle_initial_preface(tls_h2(harness.endpoint).await?).await?;
            assert_unauthenticated(tls_h2(harness.endpoint).await?).await?;
        }
        harness.shutdown()?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_idle_connection_after_response_survives_the_header_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    let mut harness = GrpcHarness::start("grpc-idle-after-response", "plaintext", 1, 3)?;
    let stream = TcpStream::connect(harness.endpoint).await?;
    let (mut sender, connection) = client::handshake(stream).await?;
    let connection = tokio::spawn(connection);

    let (response, mut body) = sender.send_request(harness.request()?, false)?;
    body.send_data(Bytes::from(harness.grpc_message("first")), true)?;
    assert_success(response).await?;
    tokio::time::sleep(Duration::from_millis(1_250)).await;

    let (response, mut body) = sender.send_request(harness.request()?, false)?;
    body.send_data(
        Bytes::from(harness.grpc_message("after-header-deadline")),
        true,
    )?;
    assert_success(response).await?;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    harness.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn grpc_excessive_peer_pings_close_plaintext_and_tls_connections()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_async_test_guard().await;
    for transport in ["plaintext", "tls"] {
        let mut harness = GrpcHarness::start(&format!("grpc-ping-{transport}"), transport, 1, 3)?;
        if transport == "plaintext" {
            reject_excessive_pings(TcpStream::connect(harness.endpoint).await?).await?;
        } else {
            reject_excessive_pings(tls_h2(harness.endpoint).await?).await?;
        }
        if transport == "plaintext" {
            assert_unauthenticated(TcpStream::connect(harness.endpoint).await?).await?;
        } else {
            assert_unauthenticated(tls_h2(harness.endpoint).await?).await?;
        }
        harness.shutdown()?;
    }
    Ok(())
}

struct GrpcHarness {
    process: Option<positron_runtime::RunningProcess>,
    endpoint: std::net::SocketAddr,
    bearer: String,
    _roots: TestRoots,
}

impl GrpcHarness {
    fn start(
        label: &str,
        transport: &str,
        streams: u16,
        idle_seconds: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let roots = TestRoots::new(label)?;
        let document = listener_document(&roots, transport, streams, idle_seconds);
        let effective = Arc::new(resolve(ConfigurationInputs::try_new(
            Some(&document),
            EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?)?);
        let paths = roots.paths()?;
        drop(InstanceBootstrap::initialize(
            &paths,
            positron_runtime::InitializationPlan::non_interactive(),
        )?);
        let claim = InstanceBootstrap::claim(&paths)?;
        let bearer = claim
            .ingest_secret()
            .ok_or("ingest secret missing")?
            .to_owned();
        drop(claim);
        let host = NativeHost::new(NativeBindings::from_effective(&effective)?);
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths, InitializationMode::ExistingOnly)
                .with_effective_configuration(effective),
            HostInputs::new(&host, &host),
        )?;
        let endpoint = address(&process.bound_endpoints(), ListenerRole::OtlpGrpc)?;
        Ok(Self {
            process: Some(process),
            endpoint,
            bearer,
            _roots: roots,
        })
    }

    fn request(&self) -> Result<Request<()>, http::Error> {
        Request::builder()
            .method("POST")
            .uri(EXPORT_PATH)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("authorization", format!("Bearer {}", self.bearer))
            .body(())
    }

    fn grpc_message(&self, body: &str) -> Vec<u8> {
        let body = otlp_body(body);
        let length = u32::try_from(body.len()).unwrap_or(u32::MAX);
        let mut message = Vec::with_capacity(body.len() + 5);
        message.push(0);
        message.extend_from_slice(&length.to_be_bytes());
        message.extend_from_slice(&body);
        message
    }

    fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let process = self.process.take().ok_or("runtime process missing")?;
        assert_eq!(
            process.shutdown(ShutdownTrigger::FirstSignal),
            positron_runtime::ExitOutcome::Graceful
        );
        Ok(())
    }
}

impl Drop for GrpcHarness {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            let _ = process.shutdown(ShutdownTrigger::DeadlineExpired);
        }
    }
}

async fn assert_success(
    response: h2::client::ResponseFuture,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_grpc_status(response, "0").await?;
    Ok(())
}

async fn assert_unauthenticated<S>(stream: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = client::handshake(stream).await?;
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri(EXPORT_PATH)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())?;
    let (response, _) = sender.send_request(request, true)?;
    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_grpc_status(response, "16").await?;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    Ok(())
}

async fn fresh_authenticated_export(
    harness: &GrpcHarness,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(harness.endpoint).await?;
    let (mut sender, connection) = client::handshake(stream)
        .await
        .map_err(|error| std::io::Error::other(format!("fresh gRPC handshake failed: {error}")))?;
    let connection = tokio::spawn(connection);
    let (response, mut body) = sender
        .send_request(harness.request()?, false)
        .map_err(|error| {
            std::io::Error::other(format!("fresh gRPC stream was refused: {error}"))
        })?;
    body.send_data(Bytes::from(harness.grpc_message("capacity-reused")), true)
        .map_err(|error| std::io::Error::other(format!("fresh gRPC body was reset: {error}")))?;
    assert_success(response)
        .await
        .map_err(|error| std::io::Error::other(format!("fresh gRPC export failed: {error}")))?;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    Ok(())
}

async fn assert_grpc_status(
    response: http::Response<h2::RecvStream>,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        drop(chunk?);
    }
    let trailers = body.trailers().await?;
    let metadata = trailers.as_ref().unwrap_or(&headers);
    assert_eq!(
        metadata
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
    Ok(())
}

async fn assert_body_deadline(
    response: http::Response<h2::RecvStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    assert_eq!(
        headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
    assert_eq!(
        headers
            .get("grpc-message")
            .and_then(|value| value.to_str().ok()),
        Some("OTLP%20request%20body%20deadline%20elapsed")
    );
    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(_) => {},
            Err(error) if error.is_reset() && error.reason() == Some(h2::Reason::NO_ERROR) => {
                return Ok(());
            },
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn reject_excessive_pings<S>(mut stream: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(H2_PREFACE).await?;
    stream.write_all(&frame(0, 4, 0, 0)).await?;
    stream.write_all(&frame(8, 6, 0, 0)).await?;
    stream.write_all(&[0; 8]).await?;
    stream.write_all(&frame(8, 6, 0, 0)).await?;
    stream.write_all(&[1; 8]).await?;
    stream.flush().await?;
    assert_closed(stream).await
}

async fn trickle_initial_preface<S>(mut stream: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&H2_PREFACE[..8]).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    stream.write_all(&H2_PREFACE[8..16]).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_closed(stream).await
}

async fn assert_closed<S>(mut stream: S) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut byte = [0_u8; 1];
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or("listener did not close")?;
        match tokio::time::timeout(remaining, stream.read(&mut byte)).await? {
            Ok(0) => return Ok(()),
            Ok(_) => {},
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Ok(());
            },
            Err(error) => return Err(error.into()),
        }
    }
}

async fn tls_h2(
    endpoint: std::net::SocketAddr,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let certificate = fixture("api-test-cert.pem");
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(certificate)? {
        roots.add(certificate?)?;
    }
    let mut configuration = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    configuration.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsConnector::from(Arc::new(configuration))
        .connect(
            ServerName::try_from("localhost".to_owned())?,
            TcpStream::connect(endpoint).await?,
        )
        .await?)
}

#[derive(Debug)]
struct RawFrame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

async fn write_frame<S>(
    stream: &mut S,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), std::io::Error>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&frame(payload.len(), kind, flags, stream_id))
        .await?;
    stream.write_all(payload).await
}

async fn next_frame<S>(stream: &mut S) -> Result<RawFrame, std::io::Error>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let length =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(RawFrame {
        kind: header[3],
        flags: header[4],
        stream: u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]),
        payload,
    })
}

async fn assert_first_stream_has_not_been_refused(
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    loop {
        let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
            Some(remaining) => remaining,
            None => return Ok(()),
        };
        match tokio::time::timeout(remaining, next_frame(stream)).await {
            Err(_) => return Ok(()),
            Ok(Ok(frame)) if frame.kind == 3 && frame.stream == 1 => {
                return Err("valid first stream was refused before the excess stream".into());
            },
            Ok(Ok(_)) => {},
            Ok(Err(error)) => return Err(error.into()),
        }
    }
}

fn grpc_headers(bearer: &str) -> Vec<u8> {
    let mut headers = vec![0x83, 0x86];
    literal_indexed_name(&mut headers, 1, "localhost");
    literal_indexed_name(&mut headers, 4, EXPORT_PATH);
    literal_indexed_name(&mut headers, 31, "application/grpc");
    literal_name(&mut headers, "te", "trailers");
    literal_indexed_name(&mut headers, 23, &format!("Bearer {bearer}"));
    headers
}

fn literal_indexed_name(target: &mut Vec<u8>, index: usize, value: &str) {
    encode_integer(target, 0, 4, index);
    encode_string(target, value);
}

fn literal_name(target: &mut Vec<u8>, name: &str, value: &str) {
    target.push(0);
    encode_string(target, name);
    encode_string(target, value);
}

fn encode_integer(target: &mut Vec<u8>, prefix: u8, bits: u8, value: usize) {
    let maximum = (1_usize << bits) - 1;
    if value < maximum {
        target.push(prefix | value as u8);
        return;
    }
    target.push(prefix | maximum as u8);
    let mut remainder = value - maximum;
    while remainder >= 128 {
        target.push((remainder as u8 & 0x7f) | 0x80);
        remainder >>= 7;
    }
    target.push(remainder as u8);
}

fn encode_string(target: &mut Vec<u8>, value: &str) {
    encode_integer(target, 0, 7, value.len());
    target.extend_from_slice(value.as_bytes());
}

fn frame(length: usize, kind: u8, flags: u8, stream: u32) -> [u8; 9] {
    let stream = stream.to_be_bytes();
    [
        (length >> 16) as u8,
        (length >> 8) as u8,
        length as u8,
        kind,
        flags,
        stream[0] & 0x7f,
        stream[1],
        stream[2],
        stream[3],
    ]
}

fn listener_document(
    roots: &TestRoots,
    transport: &str,
    streams: u16,
    idle_seconds: u16,
) -> String {
    let tls = if transport == "tls" {
        let certificate = fixture("api-test-cert.pem");
        let key = fixture("api-test-key.pem");
        format!(
            "otlp_grpc_tls_certificate_file = \"{}\"\notlp_grpc_tls_private_key_file = \"{}\"\n",
            certificate.display(),
            key.display(),
        )
    } else {
        String::new()
    };
    format!(
        "schema_version = 1\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:0\"\noperations_transport = \"plaintext\"\napi_bind_address = \"127.0.0.1:0\"\napi_transport = \"plaintext\"\notlp_grpc_bind_address = \"127.0.0.1:0\"\notlp_grpc_transport = \"{transport}\"\notlp_grpc_accepted_socket_limit = 1\notlp_grpc_per_address_accepted_socket_limit = 1\notlp_grpc_header_deadline_seconds = 1\notlp_grpc_body_deadline_seconds = 1\notlp_grpc_request_deadline_seconds = 5\notlp_grpc_idle_deadline_seconds = {idle_seconds}\notlp_grpc_http2_max_concurrent_streams = {streams}\notlp_grpc_http2_minimum_ping_interval_seconds = 2\n{tls}otlp_http_bind_address = \"127.0.0.1:0\"\notlp_http_transport = \"plaintext\"\nloki_push_bind_address = \"127.0.0.1:0\"\nloki_push_transport = \"plaintext\"\n",
        roots.parent.join("control.sock").display(),
    )
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "{}/tests/native_transport/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
}
