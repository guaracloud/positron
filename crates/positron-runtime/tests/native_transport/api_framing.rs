//! HTTP/1 framing outcomes preserved by the API HTTP/2 adapter.

use positron_runtime::{
    ApplicationRuntime, HostInputs, InitializationMode, InstanceBootstrap, ListenerRole,
    NativeHost, ServeConfiguration, ShutdownTrigger,
};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

use super::support::{TestRoots, address, assert_status, bindings, live_test_guard};

#[test]
fn api_http1_rejects_every_duplicate_content_length_before_routing()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = live_test_guard();
    let roots = TestRoots::new("api-http1-framing")?;
    let paths = roots.paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        positron_runtime::InitializationPlan::non_interactive(),
    )?);
    drop(InstanceBootstrap::claim(&paths)?);
    let host = NativeHost::new(bindings(&roots, "api-http1-framing")?);
    let process = ApplicationRuntime::start(
        ServeConfiguration::new(paths, InitializationMode::ExistingOnly),
        HostInputs::new(&host, &host),
    )?;
    let api = address(&process.bound_endpoints(), ListenerRole::Api)?;

    let identical = raw_response(
        api,
        b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
    )?;
    assert_status(identical.clone(), 400);
    assert!(identical.contains("Content-Type: application/json\r\n"));
    assert!(identical.contains("Content-Length: 0\r\n"));
    assert!(identical.contains("Connection: close\r\n"));
    let differing = raw_response(
        api,
        b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
    )?;
    assert_status(differing, 400);
    let single = raw_response(
        api,
        b"GET /v1/capabilities:negotiate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )?;
    assert_status(single, 405);

    assert_eq!(
        process.shutdown(ShutdownTrigger::FirstSignal),
        positron_runtime::ExitOutcome::Graceful
    );
    Ok(())
}

fn raw_response(address: SocketAddr, request: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}
