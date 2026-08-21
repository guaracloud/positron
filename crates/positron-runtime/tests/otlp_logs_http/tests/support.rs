use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::GzEncoder;
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InstanceBootstrap,
    NativeBindings, RunningProcess, ServeConfiguration,
};
use prost::Message;

mod transport;

pub(super) type TestError = Box<dyn std::error::Error>;

static LIVE_HTTP_TEST: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
pub(super) enum HttpEncoding {
    Json,
    Protobuf,
}

impl HttpEncoding {
    pub(super) const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Protobuf => "application/x-protobuf",
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Json => "gzip-json",
            Self::Protobuf => "gzip-protobuf",
        }
    }

    pub(super) fn encode(self, request: ExportLogsServiceRequest) -> Result<Vec<u8>, TestError> {
        match self {
            Self::Json => Ok(serde_json::to_vec(&request)?),
            Self::Protobuf => Ok(request.encode_to_vec()),
        }
    }
}

pub(super) struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub(super) const fn status(&self) -> u16 {
        self.status
    }

    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }
}

pub(super) struct LiveHttpHarness {
    _test_guard: MutexGuard<'static, ()>,
    process: Option<RunningProcess>,
    endpoint: SocketAddr,
    bearer: String,
    query_secret: String,
    roots: TestRoots,
}

impl LiveHttpHarness {
    pub(super) fn start(label: &str) -> Result<Self, TestError> {
        Self::start_with(label, std::convert::identity)
    }

    pub(super) fn start_with(
        label: &str,
        configure: impl FnOnce(ServeConfiguration) -> ServeConfiguration,
    ) -> Result<Self, TestError> {
        let test_guard = match LIVE_HTTP_TEST.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let roots = TestRoots::new(label)?;
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
        let query_secret = claim
            .query_secret()
            .ok_or("query secret missing")?
            .to_owned();
        let host = positron_runtime::NativeHost::new(bindings(&roots)?);
        let configuration = configure(ServeConfiguration::new(
            paths,
            InitializationMode::ExistingOnly,
        ));
        let process = ApplicationRuntime::start(configuration, HostInputs::new(&host, &host))?;
        let endpoint = process
            .bound_endpoints()
            .iter()
            .find(|endpoint| endpoint.role() == positron_runtime::ListenerRole::OtlpHttp)
            .and_then(positron_runtime::BoundEndpoint::socket_address)
            .ok_or("OTLP HTTP endpoint missing")?;
        Ok(Self {
            _test_guard: test_guard,
            process: Some(process),
            endpoint,
            bearer,
            query_secret,
            roots,
        })
    }

    pub(super) fn export(
        &self,
        encoding: HttpEncoding,
        request: ExportLogsServiceRequest,
    ) -> Result<HttpResponse, TestError> {
        self.request(
            &[
                ("Authorization", format!("Bearer {}", self.bearer)),
                ("Content-Type", encoding.content_type().to_owned()),
            ],
            &encoding.encode(request)?,
        )
    }

    pub(super) const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub(super) fn bearer(&self) -> &str {
        &self.bearer
    }

    pub(super) fn export_gzip(
        &self,
        encoding: HttpEncoding,
        request: ExportLogsServiceRequest,
    ) -> Result<HttpResponse, TestError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&encoding.encode(request)?)?;
        self.export_body(encoding, Some("gzip"), &encoder.finish()?)
    }

    pub(super) fn export_body(
        &self,
        encoding: HttpEncoding,
        content_encoding: Option<&str>,
        body: &[u8],
    ) -> Result<HttpResponse, TestError> {
        let mut headers = vec![
            ("Authorization", format!("Bearer {}", self.bearer)),
            ("Content-Type", encoding.content_type().to_owned()),
        ];
        if let Some(content_encoding) = content_encoding {
            headers.push(("Content-Encoding", content_encoding.to_owned()));
        }
        self.request(&headers, body)
    }

    pub(super) fn export_unauthorized(
        &self,
        encoding: HttpEncoding,
        content_encoding: Option<&str>,
        body: &[u8],
    ) -> Result<HttpResponse, TestError> {
        let mut headers = vec![("Content-Type", encoding.content_type().to_owned())];
        if let Some(content_encoding) = content_encoding {
            headers.push(("Content-Encoding", content_encoding.to_owned()));
        }
        self.request(&headers, body)
    }

    pub(super) fn export_with_tenant_hint(
        &self,
        encoding: HttpEncoding,
        tenant_hint: &str,
        body: &[u8],
    ) -> Result<HttpResponse, TestError> {
        self.request(
            &[
                ("Authorization", format!("Bearer {}", self.bearer)),
                ("Content-Type", encoding.content_type().to_owned()),
                ("X-Scope-OrgID", tenant_hint.to_owned()),
            ],
            body,
        )
    }

    pub(super) fn request(
        &self,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TestError> {
        let mut request = format!(
            "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        let response = transport::exchange(self.endpoint, request.as_bytes(), body)?;
        parse_response(&response)
    }

    pub(super) fn request_authenticated(
        &self,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TestError> {
        let mut authenticated = Vec::with_capacity(headers.len().saturating_add(1));
        authenticated.push(("Authorization", format!("Bearer {}", self.bearer)));
        authenticated.extend_from_slice(headers);
        self.request(&authenticated, body)
    }

    pub(super) fn request_stalled(
        &self,
        advertised_length: usize,
    ) -> Result<(HttpResponse, Duration), TestError> {
        let request = format!(
            "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: {advertised_length}\r\nAuthorization: Bearer {}\r\nContent-Type: application/x-protobuf\r\n\r\n",
            self.bearer
        );
        let started = Instant::now();
        let response = transport::exchange_stalled(self.endpoint, request.as_bytes())?;
        Ok((parse_response(&response)?, started.elapsed()))
    }

    pub(super) fn query_log_bodies(&self, query: &str) -> Result<Vec<String>, TestError> {
        let services = self
            .process
            .as_ref()
            .and_then(RunningProcess::services)
            .ok_or("runtime services missing")?;
        Ok(services.query_log_bodies(
            &self.query_secret,
            query,
            positron_query::QueryBudget::new(1_048_576, 16, 16, 1_048_576, 1_048_576, 60)?,
        )?)
    }

    pub(super) fn crash(&mut self) -> Result<(), TestError> {
        drop(self.process.take().ok_or("runtime process missing")?);
        Ok(())
    }

    pub(super) fn restart(&mut self) -> Result<(), TestError> {
        if self.process.is_some() {
            return Err("runtime process is already running".into());
        }
        let paths = self.roots.paths()?;
        let host = positron_runtime::NativeHost::new(bindings(&self.roots)?);
        let process = ApplicationRuntime::start(
            ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
            HostInputs::new(&host, &host),
        )?;
        self.endpoint = process
            .bound_endpoints()
            .iter()
            .find(|endpoint| endpoint.role() == positron_runtime::ListenerRole::OtlpHttp)
            .and_then(positron_runtime::BoundEndpoint::socket_address)
            .ok_or("OTLP HTTP endpoint missing")?;
        self.process = Some(process);
        Ok(())
    }
}

pub(super) fn parse_response(bytes: &[u8]) -> Result<HttpResponse, TestError> {
    let separator = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("HTTP response head missing")?;
    let head = std::str::from_utf8(&bytes[..separator])?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("HTTP status missing")?
        .parse()?;
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("malformed response header")?;
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    Ok(HttpResponse {
        status,
        headers,
        body: bytes[(separator + 4)..].to_vec(),
    })
}

pub(super) fn otlp_request(body: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            scope_logs: vec![ScopeLogs {
                log_records: vec![LogRecord {
                    time_unix_nano: 42,
                    observed_time_unix_nano: 84,
                    body: Some(AnyValue {
                        value: Some(any_value::Value::StringValue(body.to_owned())),
                    }),
                    ..LogRecord::default()
                }],
                ..ScopeLogs::default()
            }],
            ..ResourceLogs::default()
        }],
    }
}

fn bindings(roots: &TestRoots) -> Result<NativeBindings, TestError> {
    let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Ok(NativeBindings::new(
        roots.parent.join("control.sock"),
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
    )?)
}

struct TestRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    fn new(label: &str) -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent =
            PathBuf::from("/tmp").join(format!("p-http-{label}-{}-{nonce}", std::process::id()));
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

    fn paths(&self) -> Result<BootstrapPaths, positron_runtime::BootstrapFailure> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
    }
}

impl Drop for LiveHttpHarness {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            drop(process);
        }
        let _ = fs::remove_dir_all(&self.roots.parent);
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
