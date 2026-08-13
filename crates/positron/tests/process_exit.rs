//! Native binary exit and secret-safe diagnostics.

use std::process::Command;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{io::Read, io::Write, net::TcpStream};

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

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("positron-process-{}-{nonce}", std::process::id()));
    let data = root.join("data");
    let secrets = root.join("secrets");
    fs::create_dir_all(&data)?;
    fs::create_dir_all(&secrets)?;
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))?;
    let probe = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let configuration = format!(
        "schema_version = 1\n[runtime]\nshutdown_grace_seconds = 2\n[listener]\ncontrol_bind_address = \"127.0.0.1:{port}\"\n[storage]\ndata_directory = \"{}\"\nsecrets_directory = \"{}\"\n[security]\nlocal_key_file = \"{}\"\n",
        data.display(),
        secrets.display(),
        secrets.join("local-root-key").display()
    );
    let config_path = root.join("positron.toml");
    fs::write(&config_path, configuration)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args(["serve", "--init-if-empty", "--config"])
        .arg(&config_path)
        .spawn()?;
    wait_for_ready(port)?;
    std::thread::sleep(Duration::from_millis(50));
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()?;
    assert!(signal.success());
    let status = child.wait()?;
    assert_eq!(status.code(), Some(0));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
fn wait_for_ready(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.write_all(
                b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            if response.starts_with("HTTP/1.1 200 ") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("Positron did not become ready".into())
}
