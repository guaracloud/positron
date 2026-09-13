use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

const TENANT: &str = "22222222-2222-2222-2222-222222222222";

#[test]
fn retention_preview_cli_forwards_a_piped_bearer_to_the_configured_endpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/tenant-retention:preview HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer tenant-administrator\r\n")
        );
        assert!(request.contains(&format!("\r\n\r\n{{\"tenant\":\"{TENANT}\"")));
        let body = format!(
            "{{\"tenant\":\"{TENANT}\",\"retention_generation\":1,\"proposed_retention_seconds\":86400,\"catalog_identity\":\"abababababababababababababababababababababababababababababababab\",\"catalog_generation\":7,\"confirmation_digest\":\"abababababababababababababababababababababababababababababababab\",\"scopes\":[]}}"
        );
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "tenant",
            "retention",
            "preview",
            "--endpoint",
            &endpoint,
            "--credential-stdin",
            "--tenant",
            TENANT,
            "--proposed-retention-seconds",
            "86400",
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
        .write_all(b"tenant-administrator")?;
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout)?.contains(&format!("tenant={TENANT}")));
    assert!(String::from_utf8(output.stderr)?.is_empty());
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
