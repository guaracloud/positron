//! Native binary exit and secret-safe diagnostics.

use std::process::Command;

#[cfg(unix)]
use std::fs;
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
    let [operations_port, api_port, otlp_http_port] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &data,
        &secrets,
        operations_port,
        api_port,
        otlp_http_port,
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
fn fenced_native_process_stays_alive_until_signal_and_retains_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let _serial = PROCESS_TEST
        .lock()
        .map_err(|_| "process test lock poisoned")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("positron-fenced-{}-{nonce}", std::process::id()));
    let roots = ChildRoots::new(&root)?;
    fs::write(roots.data.join("foreign"), b"ambiguous")?;
    let [operations_port, api_port, otlp_http_port] = available_ports()?;
    let configuration = process_configuration(
        &root,
        &roots.data,
        &roots.secrets,
        operations_port,
        api_port,
        otlp_http_port,
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
