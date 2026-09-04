use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use positron_domain::value::{
    ByteLimit, RequestLimits, ValueLimitProfile, ValueLimitProfileCandidate, ValueLimitSet,
};
use positron_kernel::MountQualification;
use prost::Message;

use super::super::{ResponseEncoding, receive_traces};
use crate::native_host::native_http::RequestHead;
use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap, ServiceHandle};

#[test]
fn live_http_trace_export_accepts_protobuf_and_persists_before_response()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let services = ServiceHandle::new(std::sync::Arc::new(InstanceBootstrap::reopen(&paths)?))?;
    let body = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x11; 16],
                    span_id: vec![0x22; 8],
                    name: "checkout".to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    }
    .encode_to_vec();
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = listener.local_addr()?;
    let mut client = TcpStream::connect(endpoint)?;
    let (mut server, _) = listener.accept()?;
    client.write_all(&body)?;
    let response = receive_traces(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
            content_length: body.len(),
            bearer: Some(bearer),
            content_type: Some(ResponseEncoding::Protobuf.content_type().to_owned()),
            content_encoding: None,
            tenant_hint: None,
        },
        &services,
    )
    .map_err(|_| "trace HTTP response was rejected")?;
    assert_eq!(
        response.status(),
        200,
        "status={} body={:?}",
        response.status(),
        response.body()
    );
    let decoded = ExportTraceServiceResponse::decode(response.body())?;
    assert!(decoded.partial_success.is_none());
    drop(client);
    Ok(())
}

#[test]
fn live_http_trace_export_has_protobuf_json_and_gzip_parity()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let services = ServiceHandle::new(std::sync::Arc::new(InstanceBootstrap::reopen(&paths)?))?;
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x31; 16],
                    span_id: vec![0x32; 8],
                    name: "http-parity".to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let protobuf = request.encode_to_vec();
    let json = serde_json::to_vec(&request)?;
    let cases = [
        (
            protobuf.clone(),
            "Application/X-Protobuf; charset=binary",
            None,
        ),
        (protobuf.clone(), "application/x-protobuf", Some("identity")),
        (gzip(&protobuf)?, "application/x-protobuf", Some("GZip")),
        (json.clone(), "APPLICATION/JSON; charset=utf-8", None),
        (gzip(&json)?, "application/json", Some("gzip")),
    ];
    for (body, content_type, content_encoding) in cases {
        let response = receive_http(&services, &bearer, body, content_type, content_encoding)?;
        assert_eq!(
            response.status(),
            200,
            "type={content_type} encoding={content_encoding:?} body={:?}",
            response.body()
        );
        if content_type
            .split(';')
            .next()
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        {
            let value: serde_json::Value = serde_json::from_slice(response.body())?;
            assert!(value.as_object().is_some_and(|object| object.is_empty()));
        } else {
            let decoded = ExportTraceServiceResponse::decode(response.body())?;
            assert!(decoded.partial_success.is_none());
        }
    }
    Ok(())
}

#[test]
fn live_http_trace_export_rejects_missing_auth_and_unsupported_content_type()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let services = ServiceHandle::new(std::sync::Arc::new(InstanceBootstrap::reopen(&paths)?))?;
    let body = ExportTraceServiceRequest::default().encode_to_vec();
    let missing_auth = rejected(receive_http(
        &services,
        "",
        body.clone(),
        "application/x-protobuf",
        None,
    ))?;
    assert_eq!(missing_auth.status(), 401);
    let unsupported = rejected(receive_http(
        &services,
        "",
        body,
        "application/octet-stream",
        None,
    ))?;
    assert_eq!(unsupported.status(), 415);
    let unsupported_status: serde_json::Value = serde_json::from_slice(unsupported.body())?;
    assert_eq!(
        unsupported_status["message"],
        "OTLP Traces Content-Type is unsupported"
    );
    let unsupported_encoding = rejected(receive_http(
        &services,
        "",
        Vec::new(),
        "application/json",
        Some("br"),
    ))?;
    assert_eq!(unsupported_encoding.status(), 415);
    let unsupported_encoding_status: serde_json::Value =
        serde_json::from_slice(unsupported_encoding.body())?;
    assert_eq!(
        unsupported_encoding_status["message"],
        "OTLP Traces Content-Encoding is unsupported"
    );

    let malformed_gzip = receive_http(
        &services,
        &bearer,
        vec![1, 2, 3],
        "application/json",
        Some("gzip"),
    )?;
    assert_eq!(malformed_gzip.status(), 400);

    let oversized = rejected(receive_http_with_declared_length(
        &services,
        &bearer,
        vec![0],
        "application/x-protobuf",
        None,
        Some(1_048_577),
    ))?;
    assert_eq!(oversized.status(), 413);
    Ok(())
}

#[test]
fn live_http_trace_export_rejects_invalid_alias_and_compressed_body_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let services = ServiceHandle::new(std::sync::Arc::new(InstanceBootstrap::reopen(&paths)?))?;

    let invalid_alias = rejected(receive_http_with_tenant(
        &services,
        &bearer,
        Vec::new(),
        "application/x-protobuf",
        None,
        Some("tenant#alias"),
        None,
    ))?;
    assert_eq!(invalid_alias.status(), 401);

    let compressed_over_limit = rejected(receive_http_with_tenant(
        &services,
        &bearer,
        vec![0],
        "application/x-protobuf",
        Some("gzip"),
        None,
        Some(1_048_577),
    ))?;
    assert_eq!(compressed_over_limit.status(), 413);

    let json_over_limit = rejected(receive_http_with_tenant(
        &services,
        &bearer,
        vec![0],
        "application/json",
        None,
        None,
        Some(1_048_577),
    ))?;
    assert_eq!(json_over_limit.status(), 413);
    Ok(())
}

#[test]
fn live_http_trace_export_enforces_effective_gzip_limits_before_decode()
-> Result<(), Box<dyn std::error::Error>> {
    let request = ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            scope_spans: vec![ScopeSpans {
                spans: vec![Span {
                    trace_id: vec![0x71; 16],
                    span_id: vec![0x72; 8],
                    name: "effective-gzip-limits".to_owned(),
                    start_time_unix_nano: 10,
                    end_time_unix_nano: 20,
                    ..Span::default()
                }],
                ..ScopeSpans::default()
            }],
            ..ResourceSpans::default()
        }],
    };
    let protobuf = request.encode_to_vec();
    let compressed = gzip(&protobuf)?;

    let exact_compressed = profile_with_transport_limits(compressed.len(), 1_048_576)?;
    {
        let (_roots, bearer, services) = http_services_with_profile(exact_compressed)?;
        let response = receive_http(
            &services,
            &bearer,
            compressed.clone(),
            "application/x-protobuf",
            Some("gzip"),
        )?;
        assert_eq!(response.status(), 200);
    }

    let one_under_compressed = profile_with_transport_limits(compressed.len() - 1, 1_048_576)?;
    {
        let (_roots, bearer, services) = http_services_with_profile(one_under_compressed)?;
        let response = rejected(receive_http(
            &services,
            &bearer,
            compressed.clone(),
            "application/x-protobuf",
            Some("gzip"),
        ))?;
        assert_eq!(response.status(), 413);
    }

    let exact_decompressed = profile_with_transport_limits(1_048_576, protobuf.len())?;
    {
        let (_roots, bearer, services) = http_services_with_profile(exact_decompressed)?;
        let response = receive_http(
            &services,
            &bearer,
            compressed.clone(),
            "application/x-protobuf",
            Some("gzip"),
        )?;
        assert_eq!(response.status(), 200);
    }

    let one_under_decompressed = profile_with_transport_limits(1_048_576, protobuf.len() - 1)?;
    {
        let (_roots, bearer, services) = http_services_with_profile(one_under_decompressed)?;
        let response = receive_http(
            &services,
            &bearer,
            compressed,
            "application/x-protobuf",
            Some("gzip"),
        )?;
        assert_eq!(response.status(), 413);
    }
    Ok(())
}

fn rejected(
    result: Result<crate::native_host::native_http::Response, ReceiveHttpError>,
) -> Result<crate::native_host::native_http::Response, Box<dyn std::error::Error>> {
    match result {
        Err(ReceiveHttpError::Rejected(response)) => Ok(response),
        Err(ReceiveHttpError::Io(error)) => Err(Box::new(error)),
        Ok(_) => Err("request unexpectedly succeeded".into()),
    }
}

fn receive_http(
    services: &ServiceHandle,
    bearer: &str,
    body: Vec<u8>,
    content_type: &str,
    content_encoding: Option<&str>,
) -> Result<crate::native_host::native_http::Response, ReceiveHttpError> {
    receive_http_with_declared_length(services, bearer, body, content_type, content_encoding, None)
}

fn receive_http_with_declared_length(
    services: &ServiceHandle,
    bearer: &str,
    body: Vec<u8>,
    content_type: &str,
    content_encoding: Option<&str>,
    declared_length: Option<usize>,
) -> Result<crate::native_host::native_http::Response, ReceiveHttpError> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(ReceiveHttpError::Io)?;
    let endpoint = listener.local_addr().map_err(ReceiveHttpError::Io)?;
    let mut client = TcpStream::connect(endpoint).map_err(ReceiveHttpError::Io)?;
    let (mut server, _) = listener.accept().map_err(ReceiveHttpError::Io)?;
    client.write_all(&body).map_err(ReceiveHttpError::Io)?;
    let response = receive_traces(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
            content_length: declared_length.unwrap_or(body.len()),
            bearer: (!bearer.is_empty()).then(|| bearer.to_owned()),
            content_type: Some(content_type.to_owned()),
            content_encoding: content_encoding.map(str::to_owned),
            tenant_hint: None,
        },
        services,
    );
    response.map_err(ReceiveHttpError::Rejected)
}

fn receive_http_with_tenant(
    services: &ServiceHandle,
    bearer: &str,
    body: Vec<u8>,
    content_type: &str,
    content_encoding: Option<&str>,
    tenant_hint: Option<&str>,
    declared_length: Option<usize>,
) -> Result<crate::native_host::native_http::Response, ReceiveHttpError> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(ReceiveHttpError::Io)?;
    let endpoint = listener.local_addr().map_err(ReceiveHttpError::Io)?;
    let mut client = TcpStream::connect(endpoint).map_err(ReceiveHttpError::Io)?;
    let (mut server, _) = listener.accept().map_err(ReceiveHttpError::Io)?;
    client.write_all(&body).map_err(ReceiveHttpError::Io)?;
    let response = receive_traces(
        &mut server,
        RequestHead {
            method: "POST".to_owned(),
            path: "/v1/traces".to_owned(),
            content_length: declared_length.unwrap_or(body.len()),
            bearer: (!bearer.is_empty()).then(|| bearer.to_owned()),
            content_type: Some(content_type.to_owned()),
            content_encoding: content_encoding.map(str::to_owned),
            tenant_hint: tenant_hint.map(str::to_owned),
        },
        services,
    );
    response.map_err(ReceiveHttpError::Rejected)
}

enum ReceiveHttpError {
    Io(std::io::Error),
    Rejected(crate::native_host::native_http::Response),
}

impl std::fmt::Display for ReceiveHttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "HTTP test I/O failed: {error}"),
            Self::Rejected(response) => {
                write!(
                    formatter,
                    "unexpected HTTP rejection: {}",
                    response.status()
                )
            },
        }
    }
}

impl std::fmt::Debug for ReceiveHttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReceiveHttpError {}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn profile_with_transport_limits(
    compressed: usize,
    decompressed: usize,
) -> Result<ValueLimitProfile, Box<dyn std::error::Error>> {
    let system = ValueLimitProfile::release_1_system_maximum().system_limits();
    let tenant = ValueLimitSet::new(
        RequestLimits::new(
            ByteLimit::new(u32::try_from(compressed)?)?,
            ByteLimit::new(u32::try_from(decompressed)?)?,
            system.request().records(),
            system.request().aggregate_attributes(),
        ),
        system.record(),
        system.dynamic_value(),
    );
    Ok(ValueLimitProfileCandidate::new(system, Some(tenant)).validate()?)
}

fn http_services_with_profile(
    profile: ValueLimitProfile,
) -> Result<(TestRoots, String, ServiceHandle), Box<dyn std::error::Error>> {
    let roots = TestRoots::new()?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let bearer = InstanceBootstrap::claim(&paths)?
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    let mut initialized = InstanceBootstrap::reopen(&paths)?;
    initialized.value_limit_profile = profile;
    let services = ServiceHandle::new(std::sync::Arc::new(initialized))?;
    Ok((roots, bearer, services))
}

struct TestRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    fn new() -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent =
            PathBuf::from("/tmp").join(format!("p-http-traces-{}-{nonce}", std::process::id()));
        let data = parent.join("data");
        let secrets = parent.join("secrets");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&secrets)?;
        set_owner_only(&secrets)?;
        Ok(Self {
            parent,
            data,
            secrets,
        })
    }

    fn paths(&self) -> Result<BootstrapPaths, crate::BootstrapFailure> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
    }
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
