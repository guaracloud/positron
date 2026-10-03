use positron_api::maintenance::{
    MaintenanceServiceClient, MaintenanceStatusRequest, MaintenanceStatusResponse,
    MaintenanceTransport,
};

#[test]
fn maintenance_status_client_uses_the_canonical_bounded_system_administration_route()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
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
    let client = MaintenanceServiceClient::new(MaintenanceTransport::PlaintextOptOut { endpoint })?;
    assert_eq!(
        client.status("system-administrator", &MaintenanceStatusRequest {})?,
        MaintenanceStatusResponse {
            tasks: Vec::new(),
            queued: 0,
            running: 0,
            deferred: 0,
            terminal: 0,
        }
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn maintenance_status_contract_is_canonical_and_bounded() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let route = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["rpc"] == "positron.v1.MaintenanceService/Status")
        .expect("maintenance status route");
    assert_eq!(route["path"], "/v1/maintenance:status");
    assert_eq!(route["authentication"], "Bearer SystemAdministration");
    assert_eq!(route["max_request_bytes"], 128);
    assert_eq!(route["max_response_bytes"], 65_536);
}
