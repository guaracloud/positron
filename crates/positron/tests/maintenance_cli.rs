use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};

const TASK_ID: &str = "abababababababababababababababab";
const TENANT: &str = "22222222-2222-2222-2222-222222222222";
const IDEMPOTENCY_KEY: &str = "01010101-0101-0101-0101-010101010101";
const CREDENTIAL: &str = "system-administrator-secret";

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

#[test]
fn maintenance_controls_forward_bounded_requests_and_report_canonical_tasks()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for (path, expected_body, body) in [
            (
                "/v1/maintenance:explain",
                format!(r#"{{"identity":"{TASK_ID}"}}"#),
                task_response("queued"),
            ),
            (
                "/v1/maintenance:run",
                format!(
                    r#"{{"class":"compaction","tenant":"{TENANT}","signal":"logs","shard":7,"idempotency_key":"{IDEMPOTENCY_KEY}"}}"#
                ),
                task_response("queued"),
            ),
            (
                "/v1/maintenance:pause",
                format!(
                    r#"{{"identity":"{TASK_ID}","resource_generation":4,"duration_seconds":3600,"idempotency_key":"{IDEMPOTENCY_KEY}"}}"#
                ),
                control_response("deferred", 13),
            ),
            (
                "/v1/maintenance:resume",
                format!(r#"{{"identity":"{TASK_ID}","idempotency_key":"{IDEMPOTENCY_KEY}"}}"#),
                control_response("queued", 14),
            ),
        ] {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains(&format!("authorization: bearer {CREDENTIAL}\r\n"))
            );
            assert!(request.contains(&format!("\r\n\r\n{expected_body}")));
            stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });

    let explain = run_control(&endpoint, ["explain", "--task-id", TASK_ID])?;
    assert!(explain.status.success(), "{explain:?}");
    assert!(stdout(&explain)?.contains(&format!("identity={TASK_ID} class=compaction")));

    let run = run_control(
        &endpoint,
        [
            "run",
            "--tenant",
            TENANT,
            "--signal",
            "logs",
            "--shard",
            "7",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ],
    )?;
    assert!(run.status.success(), "{run:?}");
    assert!(stdout(&run)?.contains("phase=queued"));

    let pause = run_control(
        &endpoint,
        [
            "pause",
            "--task-id",
            TASK_ID,
            "--resource-generation",
            "4",
            "--duration-seconds",
            "3600",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ],
    )?;
    assert!(pause.status.success(), "{pause:?}");
    let pause_stdout = stdout(&pause)?;
    assert!(pause_stdout.contains("phase=deferred"));
    assert!(pause_stdout.contains("audit_position=13"));

    let resume = run_control(
        &endpoint,
        [
            "resume",
            "--task-id",
            TASK_ID,
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ],
    )?;
    assert!(resume.status.success(), "{resume:?}");
    let resume_stdout = stdout(&resume)?;
    assert!(resume_stdout.contains("phase=queued"));
    assert!(resume_stdout.contains("audit_position=14"));
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_explain_reports_unavailable_task_without_disclosing_stdin_credential()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut bytes = [0_u8; 4096];
        let read = stream.read(&mut bytes)?;
        let request = String::from_utf8_lossy(&bytes[..read]);
        assert!(request.starts_with("POST /v1/maintenance:explain HTTP/1.1\r\n"));
        let body = r#"{"code":"task_unavailable"}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });

    let output = run_control(&endpoint, ["explain", "--task-id", TASK_ID])?;
    assert!(!output.status.success(), "{output:?}");
    let visible = format!("{}{}", stdout(&output)?, stderr(&output)?);
    assert!(
        visible.contains("maintenance task unavailable"),
        "{visible}"
    );
    assert!(!visible.contains(CREDENTIAL), "{visible}");
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_status_run_pause_and_resume_report_canonical_failures_without_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?.to_string();
    let server = std::thread::spawn(move || -> Result<(), std::io::Error> {
        for (path, status, body) in [
            (
                "/v1/maintenance:status",
                "503 Service Unavailable",
                r#"{"code":"administration_unavailable"}"#,
            ),
            (
                "/v1/maintenance:run",
                "404 Not Found",
                r#"{"code":"source_unavailable"}"#,
            ),
            (
                "/v1/maintenance:pause",
                "409 Conflict",
                r#"{"code":"precondition_failed"}"#,
            ),
            (
                "/v1/maintenance:resume",
                "409 Conflict",
                r#"{"code":"idempotency_conflict"}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept()?;
            let mut bytes = [0_u8; 4096];
            let read = stream.read(&mut bytes)?;
            let request = String::from_utf8_lossy(&bytes[..read]);
            assert!(request.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
            stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )?;
        }
        Ok(())
    });

    assert_failure(
        run_control(&endpoint, ["status"])?,
        "maintenance administration unavailable",
    )?;
    assert_failure(
        run_control(
            &endpoint,
            [
                "run",
                "--tenant",
                TENANT,
                "--signal",
                "logs",
                "--shard",
                "7",
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ],
        )?,
        "maintenance source unavailable",
    )?;
    assert_failure(
        run_control(
            &endpoint,
            [
                "pause",
                "--task-id",
                TASK_ID,
                "--resource-generation",
                "4",
                "--duration-seconds",
                "3600",
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ],
        )?,
        "maintenance precondition failed",
    )?;
    assert_failure(
        run_control(
            &endpoint,
            [
                "resume",
                "--task-id",
                TASK_ID,
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ],
        )?,
        "maintenance idempotency conflict",
    )?;
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_pause_rejects_a_duration_outside_the_bounded_window()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_positron"))
        .args([
            "maintenance",
            "pause",
            "--endpoint",
            "127.0.0.1:1",
            "--credential-stdin",
            "--allow-plaintext",
            "--task-id",
            TASK_ID,
            "--resource-generation",
            "1",
            "--duration-seconds",
            "86401",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ])
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success(), "{output:?}");
    assert!(stderr(&output)?.contains("invalid maintenance pause request"));
    Ok(())
}

fn run_control<const N: usize>(
    endpoint: &str,
    arguments: [&str; N],
) -> Result<std::process::Output, std::io::Error> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_positron"))
        .arg("maintenance")
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
        .ok_or_else(|| std::io::Error::other("stdin unavailable"))?
        .write_all(CREDENTIAL.as_bytes())?;
    child.wait_with_output()
}

fn task_response(phase: &str) -> String {
    format!(r#"{{"task":{}}}"#, task(phase))
}

fn control_response(phase: &str, audit_position: u64) -> String {
    format!(
        r#"{{"task":{},"audit_position":{audit_position}}}"#,
        task(phase)
    )
}

fn task(phase: &str) -> String {
    format!(
        r#"{{"identity":"{TASK_ID}","class":"compaction","scope":"tenant:{TENANT}","phase":"{phase}","submitted_at_unix_seconds":123,"cancellation_requested":false}}"#
    )
}

fn stdout(output: &std::process::Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stdout.clone())
}

fn stderr(output: &std::process::Output) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(output.stderr.clone())
}

fn assert_failure(
    output: std::process::Output,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(!output.status.success(), "{output:?}");
    let visible = format!("{}{}", stdout(&output)?, stderr(&output)?);
    assert!(visible.contains(expected_message), "{visible}");
    assert!(!visible.contains(CREDENTIAL), "{visible}");
    Ok(())
}
