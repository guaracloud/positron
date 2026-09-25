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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    let pending = ConfigurationStatus::from_response(&pending_status)?;
    assert_eq!(pending.phase, "serving");
    assert!(pending.pending_restart);
    assert_eq!(pending.drift_disposition, "reconcile");
    assert_ne!(pending.effective_digest, pending.desired_digest);

    fs::write(&config_path, &base_configuration)?;
    let mut send_reload = || -> Result<(), Box<dyn std::error::Error>> {
        let status = Command::new("/bin/kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("reload signal failed with {status}").into())
    };
    let (restored_status, restored_with_retry) = match restore_configuration_with_at_most_one_retry(
        &pending,
        &mut send_reload,
        || configuration_status(operations_port, &authorization),
        &authorization,
        CONFIGURATION_RESTORE_PROBE_TIMEOUT,
    ) {
        Ok(status) => status,
        Err(error) => {
            return Err(format!(
                "configuration did not restore after reload: {error}; {}",
                terminate_and_describe_child(&mut child, &authorization)
            )
            .into());
        },
    };
    let restored = ConfigurationStatus::from_response(&restored_status)?;
    assert_eq!(restored.observed_generation, pending.observed_generation);
    assert!(restored.is_restored());

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
    assert!(reconciliation_stderr_is_exact(
        restored_with_retry,
        &String::from_utf8(output.stderr)?,
    ));
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
const CONFIGURATION_RESTORE_PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigurationStatus {
    phase: String,
    observed_generation: String,
    effective_digest: String,
    desired_digest: String,
    drift_disposition: String,
    pending_restart: bool,
}

#[cfg(unix)]
impl ConfigurationStatus {
    fn from_response(response: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if !response.starts_with("HTTP/1.1 200 ") {
            return Err("configuration status did not return HTTP 200".into());
        }
        let pending_restart = match status_value(response, "pending_restart")? {
            "true" => true,
            "false" => false,
            value => {
                return Err(format!("configuration pending_restart was invalid: {value}").into());
            },
        };
        Ok(Self {
            phase: status_value(response, "phase")?.to_owned(),
            observed_generation: status_value(response, "observed_generation")?.to_owned(),
            effective_digest: status_value(response, "effective_digest")?.to_owned(),
            desired_digest: status_value(response, "desired_digest")?.to_owned(),
            drift_disposition: status_value(response, "drift_disposition")?.to_owned(),
            pending_restart,
        })
    }

    fn is_restored(&self) -> bool {
        self.phase == "serving"
            && !self.pending_restart
            && self.drift_disposition == "none"
            && self.effective_digest == self.desired_digest
    }

    fn is_unchanged_pending_reconciliation_of(&self, pending: &Self) -> bool {
        self.phase == "serving"
            && self.pending_restart
            && self.drift_disposition == "reconcile"
            && self.observed_generation == pending.observed_generation
            && self.effective_digest == pending.effective_digest
            && self.desired_digest == pending.desired_digest
    }
}

#[cfg(unix)]
fn restore_configuration_with_at_most_one_retry(
    pending: &ConfigurationStatus,
    send_reload: &mut impl FnMut() -> Result<(), Box<dyn std::error::Error>>,
    mut observe: impl FnMut() -> Result<String, Box<dyn std::error::Error>>,
    authorization: &str,
    probe_timeout: Duration,
) -> Result<(String, bool), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + probe_timeout;
    send_reload()?;
    let mut second_reload_sent = false;

    loop {
        let last_observation = match observe() {
            Ok(response) => match ConfigurationStatus::from_response(&response) {
                Ok(status) if status.is_restored() => return Ok((response, second_reload_sent)),
                Ok(status)
                    if !second_reload_sent
                        && status.is_unchanged_pending_reconciliation_of(pending) =>
                {
                    second_reload_sent = true;
                    send_reload()?;
                    "unchanged_pending_reconciliation".to_owned()
                },
                Ok(status) => {
                    format!(
                        "phase={} pending_restart={} drift_disposition={} effective_digest={} desired_digest={}",
                        status.phase,
                        status.pending_restart,
                        status.drift_disposition,
                        status.effective_digest,
                        status.desired_digest,
                    )
                },
                Err(error) => {
                    format!(
                        "parse={error} response={:?}",
                        bounded_redacted_observation(&response, authorization)
                    )
                },
            },
            Err(error) => format!("request={error}"),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "configuration did not restore within the original bounded reload probe: {}",
                last_observation
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_accepts_immediate_serving_convergence()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let restored = configuration_status_response("serving", "12", "base", "base", "none", false)?;
    let mut signals = 0;
    let (response, retried) = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(restored.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )?;
    assert_eq!(signals, 1);
    assert!(!retried);
    assert_eq!(
        ConfigurationStatus::from_response(&response)?.observed_generation,
        "12"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_retries_once_for_unchanged_pending_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let pending_response =
        configuration_status_response("serving", "12", "old", "new", "reconcile", true)?;
    let pending = ConfigurationStatus::from_response(&pending_response)?;
    let restored = configuration_status_response("serving", "12", "base", "base", "none", false)?;
    let mut observations = [pending_response, restored].into_iter();
    let mut signals = 0;
    let (response, retried) = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || {
            observations
                .next()
                .ok_or_else(|| "configuration status observations exhausted".into())
        },
        "Bearer test-token",
        Duration::from_secs(1),
    )?;
    assert_eq!(signals, 2);
    assert!(retried);
    assert!(ConfigurationStatus::from_response(&response)?.is_restored());
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_retries_a_changed_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let changed =
        configuration_status_response("serving", "12", "old", "other", "reconcile", true)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(changed.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("a changed pending status must not trigger a second reload");
    assert_eq!(signals, 1);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_retries_a_generation_changed_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending = ConfigurationStatus::from_response(&configuration_status_response(
        "serving",
        "12",
        "old",
        "new",
        "reconcile",
        true,
    )?)?;
    let changed = configuration_status_response("serving", "13", "old", "new", "reconcile", true)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(changed.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("a changed generation must not trigger a second reload");
    assert_eq!(signals, 1);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_restore_probe_never_sends_a_third_reload_for_unresolved_pending_status()
-> Result<(), Box<dyn std::error::Error>> {
    let pending_response =
        configuration_status_response("serving", "12", "old", "new", "reconcile", true)?;
    let pending = ConfigurationStatus::from_response(&pending_response)?;
    let mut signals = 0;
    let error = restore_configuration_with_at_most_one_retry(
        &pending,
        &mut || {
            signals += 1;
            Ok(())
        },
        || Ok(pending_response.clone()),
        "Bearer test-token",
        Duration::ZERO,
    )
    .expect_err("an unresolved pending status must fail after the single permitted retry");
    assert_eq!(signals, 2);
    assert!(error.to_string().contains("original bounded reload probe"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn reconciliation_stderr_accepts_only_the_bounded_retry_variants() {
    let baseline = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=source_rejected\n";
    let publication_before_source = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=source_rejected\n";
    let duplicate_publication = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=source_rejected\n";

    assert!(reconciliation_stderr_is_exact(false, baseline));
    assert!(!reconciliation_stderr_is_exact(
        false,
        publication_before_source
    ));
    assert!(reconciliation_stderr_is_exact(true, baseline));
    assert!(reconciliation_stderr_is_exact(
        true,
        publication_before_source
    ));
    assert!(!reconciliation_stderr_is_exact(true, duplicate_publication));
}

#[cfg(unix)]
fn reconciliation_stderr_is_exact(retried: bool, stderr: &str) -> bool {
    let baseline = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=source_rejected\n";
    let publication_before_source = "positron: warning: operations transport is plaintext\npositron: configuration reload rejected category=publication_unavailable\npositron: configuration reload rejected category=source_rejected\n";
    stderr == baseline || (retried && stderr == publication_before_source)
}

#[cfg(unix)]
fn configuration_status_response(
    phase: &str,
    generation: &str,
    effective_digest: &str,
    desired_digest: &str,
    disposition: &str,
    pending_restart: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!(
        "HTTP/1.1 200 OK\r\n\r\n{{\"phase\":\"{phase}\",\"observed_generation\":{generation},\"effective_digest\":\"{effective_digest}\",\"desired_digest\":\"{desired_digest}\",\"drift_disposition\":\"{disposition}\",\"pending_restart\":{pending_restart}}}"
    ))
}

#[cfg(unix)]
fn terminate_and_describe_child(child: &mut std::process::Child, authorization: &str) -> String {
    const MAX_CHILD_STDERR_BYTES: u64 = 4 * 1024;

    let termination = match Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
    {
        Ok(status) if status.success() => "term=sent".to_owned(),
        Ok(status) => format!("term=exit_{status}"),
        Err(error) => format!("term_error={error}"),
    };
    let exit = match wait_for_child(child) {
        Ok(status) => format!("exit={status}"),
        Err(error) => format!("exit_error={error}"),
    };
    let stderr = child
        .stderr
        .take()
        .map(|mut stderr| {
            let mut bytes = Vec::with_capacity((MAX_CHILD_STDERR_BYTES + 1) as usize);
            match stderr
                .by_ref()
                .take(MAX_CHILD_STDERR_BYTES + 1)
                .read_to_end(&mut bytes)
            {
                Ok(_) => {
                    let truncated = bytes.len() > MAX_CHILD_STDERR_BYTES as usize;
                    bytes.truncate(MAX_CHILD_STDERR_BYTES as usize);
                    let observation = bounded_redacted_observation(
                        &String::from_utf8_lossy(&bytes),
                        authorization,
                    );
                    truncated
                        .then_some(format!("{observation}…<truncated>"))
                        .unwrap_or(observation)
                },
                Err(error) => format!("stderr_read_error={error}"),
            }
        })
        .unwrap_or_else(|| "stderr_unavailable".to_owned());
    format!("child_cleanup {termination} {exit} stderr={stderr:?}")
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
