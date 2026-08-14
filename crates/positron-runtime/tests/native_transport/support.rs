use super::*;
use std::sync::{Mutex, MutexGuard};

static LIVE_NATIVE_TEST: Mutex<()> = Mutex::new(());

pub(super) fn live_test_guard() -> MutexGuard<'static, ()> {
    match LIVE_NATIVE_TEST.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(super) fn bindings(
    roots: &TestRoots,
    label: &str,
) -> Result<NativeBindings, Box<dyn std::error::Error>> {
    let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    Ok(NativeBindings::new(
        roots.parent.join(format!("{label}.sock")),
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
    )?)
}

pub(super) fn address(
    endpoints: &[positron_runtime::BoundEndpoint],
    role: positron_runtime::ListenerRole,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.role() == role)
        .and_then(positron_runtime::BoundEndpoint::socket_address)
        .ok_or_else(|| format!("{role:?} endpoint missing").into())
}

pub(super) fn http(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    match stream.shutdown(std::net::Shutdown::Write) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {},
        Err(error) => return Err(error.into()),
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(String::from_utf8(bytes)?)
}

pub(super) fn assert_status(response: String, status: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "unexpected response: {response}"
    );
}

pub(super) fn assert_status_raw(
    address: SocketAddr,
    request: &[u8],
    status: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.write_all(request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert_status(response, status);
    Ok(())
}

pub(super) fn otlp_body(body: &str) -> Vec<u8> {
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
    .encode_to_vec()
}

pub(super) struct TestRoots {
    pub(super) parent: PathBuf,
    pub(super) data: PathBuf,
    pub(super) secrets: PathBuf,
}

impl TestRoots {
    pub(super) fn new(label: &str) -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent =
            PathBuf::from("/tmp").join(format!("p-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&parent)?;
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

    pub(super) fn paths(&self) -> Result<BootstrapPaths, positron_runtime::BootstrapFailure> {
        BootstrapPaths::new(&self.data, &self.secrets, MountQualification::LocalHost)
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.parent);
    }
}
