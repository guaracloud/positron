use positron_api::maintenance::{
    MaintenanceRunRequest, MaintenanceRunResponse, MaintenanceServiceClient,
    MaintenanceStatusRequest, MaintenanceStatusResponse, MaintenanceTaskStatus,
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
    let run = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["rpc"] == "positron.v1.MaintenanceService/Run")
        .expect("maintenance run route");
    assert_eq!(run["path"], "/v1/maintenance:run");
    assert_eq!(run["authentication"], "Bearer SystemAdministration");
    assert_eq!(run["max_request_bytes"], 256);
    assert_eq!(run["max_response_bytes"], 2048);
}

#[test]
fn maintenance_run_client_uses_the_canonical_explicit_scope_route()
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
        assert!(request.starts_with("POST /v1/maintenance:run HTTP/1.1\r\n"));
        assert!(request.contains(r#""class":"compaction""#));
        assert!(request.contains(r#""signal":"logs""#));
        let body = r#"{"task":{"identity":"00000000000000000000000000000001","class":"compaction","scope":"segment:00000000-0000-0000-0000-000000000001:logs:1","phase":"queued","submitted_at_unix_seconds":1,"cancellation_requested":false}}"#;
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
        client.run(
            "system-administrator",
            &MaintenanceRunRequest::new(
                "compaction".to_owned(),
                "00000000-0000-0000-0000-000000000001".to_owned(),
                "logs".to_owned(),
                1,
                "00000000-0000-0000-0000-000000000001".to_owned(),
            ),
        )?,
        MaintenanceRunResponse {
            task: MaintenanceTaskStatus {
                identity: "00000000000000000000000000000001".to_owned(),
                class: "compaction".to_owned(),
                scope: "segment:00000000-0000-0000-0000-000000000001:logs:1".to_owned(),
                phase: "queued".to_owned(),
                submitted_at_unix_seconds: 1,
                checkpoint_sequence: None,
                pause_until_unix_seconds: None,
                cancellation_requested: false,
            },
        }
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
