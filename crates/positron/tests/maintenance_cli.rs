use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

#[test]
fn maintenance_status_cli_forwards_a_piped_system_bearer() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:status HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer system-administrator\r\n")
        );
        let body = r#"{"tasks":[],"queued":0,"running":0,"deferred":0,"terminal":0}"#;
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
            "maintenance",
            "status",
            "--endpoint",
            &endpoint,
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
        .write_all(b"system-administrator")?;
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)?
            .contains("queued=0 running=0 deferred=0 terminal=0 tasks=0")
    );
    assert!(String::from_utf8(output.stderr)?.is_empty());
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
