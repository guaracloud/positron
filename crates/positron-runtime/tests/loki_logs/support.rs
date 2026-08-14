use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use positron_kernel::MountQualification;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, BoundEndpoint, InitializationMode, InstanceBootstrap,
    ListenerRole, NativeBindings, NativeHost, RunningProcess, ServeConfiguration,
};

pub(super) struct LiveLokiHarness {
    process: Option<RunningProcess>,
    bearer: String,
    query_secret: String,
    roots: TestRoots,
}

impl LiveLokiHarness {
    pub(super) fn start(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with(label, std::convert::identity)
    }

    pub(super) fn start_with(
        label: &str,
        configure: impl FnOnce(ServeConfiguration) -> ServeConfiguration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
        let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let control = roots.parent.join("control.sock");
        let bindings = NativeBindings::new(
            control, ephemeral, ephemeral, ephemeral, ephemeral, ephemeral,
        )?;
        let host = NativeHost::new(bindings);
        let configuration = configure(ServeConfiguration::new(
            paths,
            InitializationMode::ExistingOnly,
        ));
        let process = ApplicationRuntime::start(
            configuration,
            positron_runtime::HostInputs::new(&host, &host),
        )?;
        Ok(Self {
            process: Some(process),
            bearer,
            query_secret,
            roots,
        })
    }

    pub(super) fn http(
        &self,
        role: ListenerRole,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        http(self.address(role)?, method, path, headers, body.len(), body)
    }

    pub(super) fn http_with_advertised_length(
        &self,
        role: ListenerRole,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_length: usize,
    ) -> Result<String, Box<dyn std::error::Error>> {
        http(
            self.address(role)?,
            method,
            path,
            headers,
            content_length,
            &[],
        )
    }

    pub(super) fn bearer(&self) -> &str {
        &self.bearer
    }

    pub(super) fn loki_endpoint(&self) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        self.address(ListenerRole::LokiPush)
    }

    pub(super) fn query_log_bodies(
        &self,
        query: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let services = self
            .process
            .as_ref()
            .and_then(RunningProcess::services)
            .ok_or_else(|| {
                format!(
                    "runtime services missing in phase {:?}",
                    self.process.as_ref().map(RunningProcess::health)
                )
            })?;
        Ok(services.query_log_bodies(
            &self.query_secret,
            query,
            positron_query::QueryBudget::new(1_048_576, 32, 32, 1_048_576, 4, 60)?,
        )?)
    }

    pub(super) fn crash(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        drop(self.process.take().ok_or("runtime process missing")?);
        Ok(())
    }

    pub(super) fn restart(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.process.is_some() {
            return Err("runtime process is already running".into());
        }
        let paths = self.roots.paths()?;
        let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let bindings = NativeBindings::new(
            self.roots.parent.join("control-restart.sock"),
            ephemeral,
            ephemeral,
            ephemeral,
            ephemeral,
            ephemeral,
        )?;
        let host = NativeHost::new(bindings);
        self.process = Some(ApplicationRuntime::start(
            ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
            positron_runtime::HostInputs::new(&host, &host),
        )?);
        Ok(())
    }

    fn address(&self, role: ListenerRole) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        self.process
            .as_ref()
            .ok_or("runtime process missing")?
            .bound_endpoints()
            .iter()
            .find(|endpoint| endpoint.role() == role)
            .and_then(BoundEndpoint::socket_address)
            .ok_or_else(|| format!("{role:?} endpoint missing").into())
    }
}

pub(super) fn assert_status(response: String, status: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "unexpected response: {response}"
    );
}

fn http(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    content_length: usize,
    body: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    let mut writer = reader.try_clone()?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
        content_length
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    let response = std::thread::scope(|scope| {
        let write = scope.spawn(move || -> Result<(), std::io::Error> {
            writer.write_all(request.as_bytes())?;
            match writer.write_all(body) {
                Ok(()) => {},
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                    ) => {},
                Err(error) => return Err(error),
            }
            match writer.shutdown(Shutdown::Write) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
                Err(error) => Err(error),
            }
        });
        let mut response = String::new();
        match reader.read_to_string(&mut response) {
            Ok(_) => {},
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
            Err(error) => return Err(error),
        }
        write
            .join()
            .map_err(|_| std::io::Error::other("request writer panicked"))??;
        Ok::<_, std::io::Error>(response)
    })?;
    Ok(response)
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
            PathBuf::from("/tmp").join(format!("pl-{label}-{}-{nonce}", std::process::id()));
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
