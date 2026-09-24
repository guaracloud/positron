//! Native binary exit and secret-safe diagnostics.

use std::process::Command;

#[cfg(unix)]
use positron_kernel::MountQualification;
#[cfg(unix)]
use positron_runtime::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{io::Read, io::Write, net::TcpStream};

#[cfg(unix)]
static PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[path = "process_exit/support.rs"]
mod support;
use support::*;

#[test]
fn invalid_configuration_has_a_stable_nonzero_exit_without_echoing_input()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_marker = "must-not-appear";
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "serve",
            "--set",
            &format!("storage.data_directory={secret_marker}"),
        ])
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(stderr, "positron: configuration rejected\n");
    assert!(!stderr.contains(secret_marker));
    Ok(())
}

#[test]
fn unknown_command_has_the_usage_exit() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("unknown")
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "positron: invalid command line\n"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn first_os_signal_drains_and_exits_successfully() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("positron-process-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data).map_err(|error| format!("create data: {error}"))?;
    fs::create_dir_all(&secrets).map_err(|error| format!("create secrets: {error}"))?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect secrets: {error}"))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &data,
        &secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)
        .map_err(|error| format!("write configuration: {error}"))?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()
        .map_err(|error| format!("spawn positron: {error}"))?;
    wait_for_ready(operations_port)?;
    std::thread::sleep(Duration::from_millis(50));
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .map_err(|error| format!("signal positron: {error}"))?;
    assert!(signal.success());
    let status = child.wait()?;
    assert_eq!(status.code(), Some(0));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn sighup_reloads_a_valid_candidate_and_keeps_serving_after_a_rejected_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-reload-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    let base_configuration = process_configuration(
        &root,
        &data,
        &secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    fs::write(&config_path, &base_configuration)?;
    let bootstrap_paths = BootstrapPaths::new(&data, &secrets, MountQualification::LocalHost)?;
    drop(InstanceBootstrap::initialize(
        &bootstrap_paths,
        InitializationPlan::non_interactive(),
    )?);
    let authorization = format!(
        "Bearer {}",
        InstanceBootstrap::claim(&bootstrap_paths)?.secret()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--config"])
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_ready(operations_port)?;

    fs::write(
        &config_path,
        format!("{base_configuration}\n[diagnostics]\nlog_level = \"debug\"\n"),
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait()?.is_none());
    wait_for_ready(operations_port)?;

    let restart_required_configuration = base_configuration.replacen(
        "shutdown_grace_seconds = 2",
        "shutdown_grace_seconds = 60",
        1,
    );
    fs::write(&config_path, restart_required_configuration)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let pending_status = wait_for_configuration_status(
        operations_port,
        &authorization,
        &[
            "\"pending_restart\":true",
            "\"drift_disposition\":\"reconcile\"",
        ],
    )?;
    let pending_generation = status_value(&pending_status, "observed_generation")?;
    assert_ne!(
        status_value(&pending_status, "effective_digest")?,
        status_value(&pending_status, "desired_digest")?
    );

    fs::write(&config_path, &base_configuration)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let restored_status = wait_for_configuration_status(
        operations_port,
        &authorization,
        &[
            "\"pending_restart\":false",
            "\"drift_disposition\":\"none\"",
        ],
    )?;
    assert_eq!(
        status_value(&restored_status, "observed_generation")?,
        pending_generation
    );
    assert_eq!(
        status_value(&restored_status, "effective_digest")?,
        status_value(&restored_status, "desired_digest")?
    );

    fs::write(
        &config_path,
        "schema_version = 1\n[diagnostics]\nlog_level = \"invalid\"\n",
    )?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait()?.is_none());
    wait_for_ready(operations_port)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let output = child.wait_with_output()?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "positron: warning: operations transport is plaintext\npositron: configuration reload rejected\n"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn status_value<'response>(
    response: &'response str,
    field: &str,
) -> Result<&'response str, Box<dyn std::error::Error>> {
    let prefix = format!("\"{field}\":");
    let value = response
        .split_once(&prefix)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("status field {field} missing"))?;
    value
        .split([',', '}'])
        .next()
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| format!("status field {field} missing value").into())
}

#[cfg(unix)]
#[test]
fn sighup_during_recovery_does_not_interrupt_native_startup()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "positron-recovery-sighup-{}-{nonce}",
        std::process::id()
    ));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let config_path = root.join("positron.toml");
    fs::write(
        &config_path,
        process_configuration(
            &root,
            &data,
            &secrets,
            [
                operations_port,
                api_port,
                otlp_grpc_port,
                otlp_http_port,
                loki_push_port,
            ],
        ),
    )?;
    let ownership = positron_kernel::PrimaryDataVolume::acquire(
        &data,
        positron_kernel::MountQualification::LocalHost,
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()?;

    wait_for_readiness(operations_port, "HTTP/1.1 503 ")?;
    assert!(
        Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait()?.is_none());

    drop(ownership);
    wait_for_ready(operations_port)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(child.wait()?.code(), Some(0));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn fenced_native_process_stays_alive_until_signal_and_retains_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-fenced-{}-{nonce}", std::process::id()));
    let roots = ChildRoots::new(&root)?;
    fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let [
        operations_port,
        api_port,
        otlp_grpc_port,
        otlp_http_port,
        loki_push_port,
    ] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &roots.data,
        &roots.secrets,
        [
            operations_port,
            api_port,
            otlp_grpc_port,
            otlp_http_port,
            loki_push_port,
        ],
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()?;

    wait_for_readiness(operations_port, "HTTP/1.1 503 ")?;
    assert!(child.try_wait()?.is_none());
    assert!(
        positron_kernel::PrimaryDataVolume::acquire(
            &roots.data,
            positron_kernel::MountQualification::LocalHost,
        )
        .is_err()
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(wait_for_child(&mut child)?.code(), Some(0));
    assert!(
        positron_kernel::PrimaryDataVolume::acquire(
            &roots.data,
            positron_kernel::MountQualification::LocalHost,
        )
        .is_ok()
    );
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn second_os_signal_escalates_to_forced_exit() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-force-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root)?;
    let ready = root.join("ready");
    let draining = root.join("draining");
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "blocked_shutdown_child_fixture",
            "--nocapture",
        ])
        .env("POSITRON_BLOCKED_CHILD", &root)
        .spawn()?;
    wait_for_file(&ready)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    wait_for_file(&draining)?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    assert_eq!(child.wait()?.code(), Some(4));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
#[ignore = "owned subprocess fixture"]
fn blocked_shutdown_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
    use positron_kernel::MountQualification;
    use positron_runtime::{
        ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, ServeConfiguration,
        ShutdownTrigger,
    };

    let Some(root) = std::env::var_os("POSITRON_BLOCKED_CHILD").map(std::path::PathBuf::from)
    else {
        return Ok(());
    };
    let roots = ChildRoots::new(&root)?;
    let host = BlockedHost;
    let paths = BootstrapPaths::new(&roots.data, &roots.secrets, MountQualification::LocalHost)?;
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    )?;
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::signal::SIGINT,
        signal_hook::consts::signal::SIGTERM,
    ])?;
    fs::write(root.join("ready"), b"ready")?;
    let Some(_) = signals.forever().next() else {
        return Err("signal stream ended".into());
    };
    let mut draining = process.begin_shutdown();
    fs::write(root.join("draining"), b"draining")?;
    loop {
        if signals.pending().next().is_some() {
            let outcome = draining.finish(ShutdownTrigger::SecondSignal);
            std::process::exit(if outcome == positron_runtime::ExitOutcome::Forced {
                4
            } else {
                3
            });
        }
        assert!(!draining.poll()?);
        std::thread::yield_now();
    }
}
