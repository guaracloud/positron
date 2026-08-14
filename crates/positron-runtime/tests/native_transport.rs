//! Real loopback transport integration tests.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
use positron_kernel::MountQualification;
use positron_query::QueryBudget;
use positron_runtime::{
    ApplicationRuntime, BootstrapPaths, HostInputs, InitializationMode, InstanceBootstrap,
    NativeBindings, NativeHost, ServeConfiguration, ShutdownTrigger,
};
use prost::Message;

#[path = "native_transport/support.rs"]
mod support;
use support::*;

#[test]
fn loopback_otlp_is_authenticated_durable_and_observable_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("loopback")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let first_bindings = bindings(&roots, "first")?;
    let first_host = NativeHost::new(first_bindings);
    let first = ApplicationRuntime::start(
        ServeConfiguration::new(paths.clone(), InitializationMode::ExistingOnly),
        HostInputs::new(&first_host, &first_host),
    )?;
    let endpoints = first.bound_endpoints();
    let operations = address(&endpoints, positron_runtime::ListenerRole::Operations)?;
    let api = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let otlp = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;

    assert_status(http(operations, "GET", "/health/ready", &[], &[])?, 200);
    let capability = http(
        api,
        "POST",
        "/v1/capabilities:negotiate",
        &[],
        br#"{"api_major":1,"capability":1}"#,
    )?;
    assert_status(capability.clone(), 200);
    assert!(capability.contains("\"availability\":1"));

    let unauthorized = http(otlp, "POST", "/v1/logs", &[], &[0xff])?;
    assert_status(unauthorized, 401);
    let body = otlp_body("durable-loopback");
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("ingest secret missing")?
    );
    let accepted = http(
        otlp,
        "POST",
        "/v1/logs",
        &[("Authorization", &authorization)],
        &body,
    )?;
    assert_status(accepted.clone(), 200);
    assert!(accepted.contains("\"accepted\":1"));

    let query_secret = claim
        .query_secret()
        .ok_or("query secret missing")?
        .to_owned();
    let ingest_secret = claim
        .ingest_secret()
        .ok_or("ingest secret missing")?
        .to_owned();
    drop(first);
    assert!(TcpStream::connect_timeout(&otlp, Duration::from_millis(100)).is_err());

    let second_bindings = bindings(&roots, "second")?;
    let second_host = NativeHost::new(second_bindings);
    let second = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&second_host, &second_host),
    )?;
    let bodies = second
        .services()
        .ok_or("serving process omitted services")?
        .query_log_bodies(
            &query_secret,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_048_576, 16, 16, 1_048_576, 4, 60)?,
        )?;
    assert_eq!(bodies, ["durable-loopback"]);
    assert!(matches!(
        second.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    ));
    assert!(!ingest_secret.is_empty());
    Ok(())
}

#[test]
fn loopback_transport_enforces_bounded_http_and_typed_statuses()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = TestRoots::new("bounds")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let host = NativeHost::new(bindings(&roots, "bounds")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let endpoints = process.bound_endpoints();
    let operations = address(&endpoints, positron_runtime::ListenerRole::Operations)?;
    let api = address(&endpoints, positron_runtime::ListenerRole::Api)?;
    let otlp = address(&endpoints, positron_runtime::ListenerRole::OtlpHttp)?;

    assert_status(http(operations, "GET", "/health/live", &[], &[])?, 200);
    assert_status(http(operations, "GET", "/health/ready", &[], &[])?, 200);
    assert_status(http(operations, "GET", "/missing", &[], &[])?, 404);
    assert_status(
        http(
            operations,
            "POST",
            "/v1/logs",
            &[("Authorization", "Bearer invalid")],
            &[0xff],
        )?,
        404,
    );
    assert_status_raw(
        operations,
        b"POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048576\r\n\r\n",
        404,
    )?;
    assert_status(
        http(
            operations,
            "POST",
            "/v1/capabilities:negotiate",
            &[],
            br#"{"api_major":1,"capability":1}"#,
        )?,
        404,
    );
    assert_status(http(api, "GET", "/health/ready", &[], &[])?, 404);
    assert_status(
        http(
            api,
            "POST",
            "/v1/logs",
            &[("Authorization", "Bearer invalid")],
            &[0xff],
        )?,
        404,
    );
    assert_status(http(otlp, "GET", "/health/live", &[], &[])?, 404);
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/capabilities:negotiate",
            &[],
            br#"{"api_major":1,"capability":1}"#,
        )?,
        404,
    );
    assert_status(
        http(api, "GET", "/v1/capabilities:negotiate", &[], &[])?,
        405,
    );
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.0\r\nHost: localhost\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        400,
    )?;
    assert_status(
        http(api, "POST", "/v1/capabilities:negotiate", &[], &[b'x'; 65])?,
        413,
    );
    assert_status(
        http(api, "POST", "/v1/capabilities:negotiate", &[], b"not-json")?,
        400,
    );
    let refused = http(
        api,
        "POST",
        "/v1/capabilities:negotiate",
        &[],
        br#"{"api_major":2,"capability":1}"#,
    )?;
    assert_status(refused.clone(), 200);
    assert!(refused.contains("\"refusal\":{"));
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\ninvalid-header\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        operations,
        b"GET /health/live HTTP/1.1\r\nContent-Length: invalid\r\n\r\n",
        400,
    )?;
    assert_status_raw(
        api,
        b"POST /v1/capabilities:negotiate HTTP/1.1\r\nContent-Length: 5\r\n\r\nx",
        400,
    )?;
    let mut invalid_utf8 = b"GET /health/live HTTP/1.1\r\nX: ".to_vec();
    invalid_utf8.push(0xff);
    invalid_utf8.extend_from_slice(b"\r\n\r\n");
    assert_status_raw(operations, &invalid_utf8, 400)?;
    let mut oversized_header = vec![b'x'; 8 * 1024];
    oversized_header[..27].copy_from_slice(b"GET /health/live HTTP/1.1\r\n");
    assert_status_raw(operations, &oversized_header, 431)?;
    let authorization = format!(
        "Bearer {}",
        claim.ingest_secret().ok_or("ingest secret missing")?
    );
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/logs",
            &[("Authorization", &authorization)],
            &[0xff],
        )?,
        400,
    );
    assert_status(
        http(
            otlp,
            "POST",
            "/v1/logs",
            &[("Authorization", "Bearer invalid")],
            &[0xff],
        )?,
        401,
    );
    assert_status_raw(operations, b"GET /health/live HTTP/1.1\r\n", 400)?;
    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

#[test]
fn native_bindings_reject_unsafe_and_colliding_endpoints() -> Result<(), Box<dyn std::error::Error>>
{
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let wildcard = "0.0.0.0:1".parse()?;
    assert!(
        NativeBindings::new(
            PathBuf::from("relative.sock"),
            loopback,
            loopback,
            loopback,
            loopback,
        )
        .is_err()
    );
    assert!(
        NativeBindings::new(
            PathBuf::from("/tmp/control.sock"),
            wildcard,
            loopback,
            loopback,
            loopback
        )
        .is_err()
    );

    let roots = TestRoots::new("collision")?;
    let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let occupied_address = occupied.local_addr()?;
    let bindings = NativeBindings::new(
        roots.parent.join("collision.sock"),
        occupied_address,
        loopback,
        loopback,
        loopback,
    )?;
    let host = NativeHost::new(bindings);
    let paths = roots.paths()?;
    let result = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::InitializeIfEmpty),
        HostInputs::new(&host, &host),
    );
    assert!(matches!(
        result,
        Err(positron_runtime::ExitOutcome::ListenerUnavailable(
            positron_runtime::ListenerRole::Operations
        ))
    ));
    Ok(())
}
