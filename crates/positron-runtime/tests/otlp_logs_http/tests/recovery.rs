use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use super::support::{HttpEncoding, LiveHttpHarness, otlp_request};

const QUERY: &str = "logs | range query_time 0 100 | limit 16";

#[test]
fn acknowledged_log_survives_process_drop_and_restart() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = LiveHttpHarness::start("http-restart")?;
    let response = harness.export(
        HttpEncoding::Protobuf,
        otlp_request("http-survives-restart"),
    )?;
    assert_eq!(response.status(), 200);

    harness.crash()?;
    harness.restart()?;

    assert_eq!(harness.query_log_bodies(QUERY)?, ["http-survives-restart"]);
    Ok(())
}

#[test]
fn retry_after_lost_response_is_explicitly_at_least_once() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = LiveHttpHarness::start("http-lost-response")?;
    let request = otlp_request("http-at-least-once");
    let body = HttpEncoding::Protobuf.encode(request.clone())?;
    send_without_reading_response(harness.endpoint(), harness.bearer(), &body)?;

    assert_eq!(wait_for_records(&harness, 1)?, ["http-at-least-once"]);

    assert_eq!(
        harness.export(HttpEncoding::Protobuf, request)?.status(),
        200
    );
    assert_eq!(
        wait_for_records(&harness, 2)?,
        ["http-at-least-once", "http-at-least-once"]
    );
    Ok(())
}

fn wait_for_records(
    harness: &LiveHttpHarness,
    expected: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // Coverage instrumentation can delay the background ingest/query workers
    // beyond the ordinary socket timeout while the durable outcome is still
    // progressing. Keep this bounded but distinct from connection I/O.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(records) = harness.query_log_bodies(QUERY)
            && records.len() == expected
        {
            return Ok(records);
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                format!("did not observe {expected} durable records before timeout").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn send_without_reading_response(
    endpoint: SocketAddr,
    bearer: &str,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let head = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/x-protobuf\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response_available = [0_u8; 1];
    if stream.peek(&mut response_available)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "server closed before an unread response was available",
        ));
    }
    Ok(())
}
