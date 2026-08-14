use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_kernel::MountQualification;
use positron_runtime::{BootstrapPaths, NativeBindings};

pub(super) fn bindings(
    roots: &TestRoots,
    label: &str,
) -> Result<NativeBindings, Box<dyn std::error::Error>> {
    let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let control = roots.parent.join(format!("{label}.sock"));
    Ok(NativeBindings::new(
        control, ephemeral, ephemeral, ephemeral, ephemeral,
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

pub(super) struct TestRoots {
    parent: PathBuf,
    data: PathBuf,
    secrets: PathBuf,
}

impl TestRoots {
    pub(super) fn new(label: &str) -> Result<Self, std::io::Error> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let parent =
            PathBuf::from("/tmp").join(format!("p-grpc-{label}-{}-{nonce}", std::process::id()));
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
        if let Err(error) = fs::remove_dir_all(&self.parent) {
            eprintln!("temporary test root cleanup failed: {error}");
        }
    }
}
