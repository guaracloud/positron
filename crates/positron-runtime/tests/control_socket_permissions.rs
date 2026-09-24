//! Native Control socket permissions are enforced independently of the caller's umask.

#[cfg(unix)]
#[allow(dead_code)]
#[path = "support/process_roots.rs"]
mod roots;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, ListenerFactory, NativeBindings,
    NativeHost, ServeConfiguration, ShutdownTrigger,
};
#[cfg(unix)]
use roots::TestRoots;

#[cfg(unix)]
const CHILD_MARKER: &str = "POSITRON_CONTROL_SOCKET_PERMISSIONS_CHILD";

/// Runs the real native bind path under umask 000 in a subprocess, so this
/// test cannot affect the parallel test process's process-global umask.
#[cfg(unix)]
#[test]
fn native_control_socket_stays_owner_only_with_a_permissive_umask()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os(CHILD_MARKER).is_some() {
        return assert_child_socket_permissions();
    }

    let test_binary = std::env::current_exe()?;
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 000; exec \"$@\"")
        .arg("positron-control-socket-permissions-child")
        .arg(test_binary)
        .arg("--exact")
        .arg("native_control_socket_stays_owner_only_with_a_permissive_umask")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()?;
    assert!(status.success(), "permission-check child process failed");
    Ok(())
}

#[cfg(unix)]
fn assert_child_socket_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("control-socket-permissions")?;
    let control = std::path::PathBuf::from("/tmp")
        .join(format!("positron-control-mode-{}.sock", std::process::id()));
    let host = NativeHost::new(NativeBindings::new(
        control.clone(),
        loopback_any(),
        loopback_any(),
        loopback_any(),
        loopback_any(),
        loopback_any(),
    )?);
    let listeners: &dyn ListenerFactory = &host;
    let paths = roots.bootstrap_paths()?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(listeners, &host),
    )
    .map_err(|outcome| format!("native startup failed: {outcome:?}"))?;

    let permissions = fs::metadata(&control)?.permissions().mode() & 0o777;
    let _ = process.shutdown(ShutdownTrigger::FirstSignal);
    assert_eq!(
        permissions, 0o600,
        "Control socket must not be group- or world-accessible"
    );
    Ok(())
}

#[cfg(unix)]
fn loopback_any() -> std::net::SocketAddr {
    std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        0,
    ))
}
