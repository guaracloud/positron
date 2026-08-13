use super::*;

#[cfg(unix)]
pub(super) struct ChildRoots {
    pub(super) data: std::path::PathBuf,
    pub(super) secrets: std::path::PathBuf,
}

#[cfg(unix)]
impl ChildRoots {
    pub(super) fn new(root: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let data = root.join("data");
        let secrets = root.join("secrets");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&secrets)?;
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
        Ok(Self { data, secrets })
    }
}

#[cfg(unix)]
pub(super) struct BlockedHost;

#[cfg(unix)]
impl positron_runtime::ListenerFactory for BlockedHost {
    fn bind(
        &self,
        request: positron_runtime::ListenerRequest,
    ) -> Result<Box<dyn positron_runtime::BoundListener>, positron_runtime::ListenerFailure> {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        let endpoint = if request.role() == positron_runtime::ListenerRole::Control {
            positron_runtime::BoundEndpoint::control(std::path::PathBuf::from(
                "/tmp/positron-blocked-child.sock",
            ))?
        } else {
            positron_runtime::BoundEndpoint::tcp(
                request.role(),
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_498)),
            )?
        };
        Ok(Box::new(ChildListener(endpoint)))
    }
}

#[cfg(unix)]
struct ChildListener(positron_runtime::BoundEndpoint);

#[cfg(unix)]
impl positron_runtime::BoundListener for ChildListener {
    fn endpoint(&self) -> &positron_runtime::BoundEndpoint {
        &self.0
    }
}

#[cfg(unix)]
impl positron_runtime::TaskRegistrar for BlockedHost {
    fn register(
        &self,
        _role: positron_runtime::TaskRole,
    ) -> Result<Box<dyn positron_runtime::RegisteredTask>, positron_runtime::TaskFailure> {
        Ok(Box::new(BlockedTask))
    }
}

#[cfg(unix)]
struct BlockedTask;

#[cfg(unix)]
impl positron_runtime::RegisteredTask for BlockedTask {
    fn spawn(
        self: Box<Self>,
        cancellation: positron_runtime::TaskCancellation,
        _health: positron_runtime::HealthState,
        _services: Option<positron_runtime::ServiceHandle>,
    ) -> Result<Box<dyn positron_runtime::RunningTask>, positron_runtime::TaskFailure> {
        Ok(Box::new(BlockedTaskHandle(cancellation)))
    }
}

#[cfg(unix)]
struct BlockedTaskHandle(positron_runtime::TaskCancellation);

#[cfg(unix)]
impl positron_runtime::RunningTask for BlockedTaskHandle {
    fn poll_join(
        &mut self,
    ) -> Result<Option<positron_runtime::TaskJoinOutcome>, positron_runtime::TaskFailure> {
        assert!(self.0.is_cancelled());
        Ok(None)
    }

    fn join(&mut self) -> Result<positron_runtime::TaskJoinOutcome, positron_runtime::TaskFailure> {
        panic!("blocked child join must remain interruptible")
    }

    fn abort(&mut self) -> Result<(), positron_runtime::TaskFailure> {
        assert!(self.0.is_cancelled());
        Ok(())
    }
}

#[cfg(unix)]
pub(super) fn wait_for_ready(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_readiness(port, "HTTP/1.1 200 ")
}

#[cfg(unix)]
pub(super) fn wait_for_readiness(
    port: u16,
    expected_status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.write_all(
                b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            if response.starts_with(expected_status) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("Positron did not become ready".into())
}

#[cfg(unix)]
pub(super) fn wait_for_file(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if path.is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("child process did not reach expected phase".into())
}

#[cfg(unix)]
pub(super) fn wait_for_child(
    child: &mut std::process::Child,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill()?;
    let _status = child.wait()?;
    Err("child process did not exit".into())
}

#[cfg(unix)]
pub(super) fn available_ports() -> Result<[u16; 3], Box<dyn std::error::Error>> {
    let mut probes = Vec::with_capacity(3);
    for _ in 0..3 {
        probes.push(
            std::net::TcpListener::bind(("127.0.0.1", 0))
                .map_err(|error| format!("bind port probe: {error}"))?,
        );
    }
    let mut ports = [0; 3];
    for (port, probe) in ports.iter_mut().zip(&probes) {
        *port = probe
            .local_addr()
            .map_err(|error| format!("inspect port probe: {error}"))?
            .port();
    }
    Ok(ports)
}

#[cfg(unix)]
pub(super) fn process_configuration(
    root: &std::path::Path,
    data: &std::path::Path,
    secrets: &std::path::Path,
    operations_port: u16,
    api_port: u16,
    otlp_http_port: u16,
) -> String {
    format!(
        "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 2\n[listener]\ncontrol_path = \"{}\"\noperations_bind_address = \"127.0.0.1:{operations_port}\"\napi_bind_address = \"127.0.0.1:{api_port}\"\notlp_http_bind_address = \"127.0.0.1:{otlp_http_port}\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        std::path::Path::new("/tmp")
            .join(root.file_name().unwrap_or_default())
            .with_extension("sock")
            .display(),
        data.display(),
        secrets.display(),
        secrets.join("local-root-key.v1").display()
    )
}
