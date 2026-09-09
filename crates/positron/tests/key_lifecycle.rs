use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InitializationPlan,
    InstanceBootstrap, NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

#[test]
fn cli_manages_keys_through_authenticated_running_api_without_redisplay()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::PathBuf::from("/tmp").join(format!(
        "p-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("data"))?;
    std::fs::create_dir_all(root.join("secrets"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join("secrets"), std::fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        positron_kernel::MountQualification::LocalHost,
    )?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let ephemeral = "127.0.0.1:0".parse()?;
    let host = NativeHost::new(NativeBindings::new(
        root.join("control.sock"),
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
        ephemeral,
    )?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let address = process
        .bound_endpoints()
        .iter()
        .find(|endpoint| endpoint.role() == positron_runtime::ListenerRole::Api)
        .and_then(positron_runtime::BoundEndpoint::socket_address)
        .ok_or("API absent")?
        .to_string();
    let create = [
        "create",
        "--scope",
        "query",
        "--expected-generation",
        "1",
        "--idempotency-key",
        "11111111-1111-1111-1111-111111111111",
    ];
    assert_eq!(raw_status(&address, &[], b"not-json")?, 401);
    assert_eq!(raw_status(&address, &[claim.secret()], b"not-json")?, 400);
    assert_eq!(
        raw_status(
            &address,
            &[claim.secret(), claim.secret()],
            br#"{"action":"list"}"#
        )?,
        400
    );
    assert_eq!(
        raw_status(
            &address,
            &[claim.secret()],
            br#"{"action":"list","tenant":"forged"}"#
        )?,
        400
    );
    assert_eq!(
        raw_status(
            &address,
            &[claim.secret()],
            br#"{"action":"create","scope":"system_administration","expected_generation":1,"idempotency_key":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#
        )?,
        400
    );
    let first = invoke(&address, claim.secret(), &create)?;
    assert!(first.status.success());
    let first = String::from_utf8(first.stdout)?;
    let principal = first
        .lines()
        .find_map(|line| line.strip_prefix("principal="))
        .ok_or("principal absent")?;
    let secret = first
        .lines()
        .find_map(|line| line.strip_prefix("secret="))
        .ok_or("secret absent")?;
    let retry = invoke(&address, claim.secret(), &create)?;
    assert!(retry.status.success());
    assert!(!String::from_utf8(retry.stdout)?.contains(secret));
    let listed = invoke(&address, claim.secret(), &["list"])?;
    assert!(listed.status.success());
    let listed = String::from_utf8(listed.stdout)?;
    assert!(listed.contains(principal));
    assert!(!listed.contains(secret));
    assert!(!invoke(&address, secret, &["list"])?.status.success());
    assert_eq!(raw_status(&address, &[claim.secret()], br#"{"action":"create","scope":"query","expected_generation":1,"idempotency_key":"44444444-4444-4444-4444-444444444444"}"#)?, 409);
    let rotated = invoke(
        &address,
        claim.secret(),
        &[
            "rotate",
            "--principal",
            principal,
            "--expected-generation",
            "2",
            "--idempotency-key",
            "22222222-2222-2222-2222-222222222222",
        ],
    )?;
    assert!(rotated.status.success());
    assert!(String::from_utf8(rotated.stdout)?.contains("secret="));
    let revoked = invoke(
        &address,
        claim.secret(),
        &[
            "revoke",
            "--principal",
            principal,
            "--expected-generation",
            "3",
            "--idempotency-key",
            "33333333-3333-3333-3333-333333333333",
        ],
    )?;
    assert!(revoked.status.success());
    let inspected = invoke(
        &address,
        claim.secret(),
        &["scope-inspect", "--principal", principal],
    )?;
    assert!(inspected.status.success());
    assert!(String::from_utf8(inspected.stdout)?.contains("active=false"));
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn cli_reports_a_typed_idempotency_conflict_without_echoing_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = "{\"code\":\"idempotency_conflict\"}";
        stream.write_all(
            format!(
                "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let output = invoke(&endpoint, "credential-canary", &["list"])?;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(
        stderr,
        "positron: idempotency conflict; inspect current state before retrying\n"
    );
    assert!(!stderr.contains("credential-canary"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn cli_reports_invalid_request_without_echoing_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request)?;
        let body = r#"{"code":"invalid_request"}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let output = invoke(&endpoint, "credential-canary", &["list"])?;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(
        stderr,
        "positron: invalid key request; correct the request before retrying\n"
    );
    assert!(!stderr.contains("credential-canary"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

fn raw_status(
    endpoint: &str,
    credentials: &[&str],
    body: &[u8],
) -> Result<u16, Box<dyn std::error::Error>> {
    let mut stream = std::net::TcpStream::connect(endpoint)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut head = format!(
        "POST /v1/api-keys:manage HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n",
        body.len()
    );
    for credential in credentials {
        head.push_str(&format!("Authorization: Bearer {credential}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    let mut response = String::new();
    // A rejected header may close without consuming the request body.
    match stream.read_to_string(&mut response) {
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(error) => return Err(error.into()),
    }
    Ok(response
        .split_whitespace()
        .nth(1)
        .ok_or("status absent")?
        .parse()?)
}

fn invoke(
    endpoint: &str,
    credential: &str,
    arguments: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("key")
        .args(arguments)
        .args([
            "--endpoint",
            endpoint,
            "--credential-stdin",
            "--allow-plaintext",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin unavailable")?
        .write_all(credential.as_bytes())?;
    Ok(child.wait_with_output()?)
}
