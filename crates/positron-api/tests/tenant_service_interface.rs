use positron_api::tenant_service::{
    MAX_RESPONSE_BYTES, TenantCreateRequest, TenantDescriptor, TenantDisplayNameUpdateRequest,
    TenantInspectRequest, TenantLifecycleState, TenantListResponse, TenantServiceClient,
    TenantServiceClientFailure, TenantServiceTransport,
};
use std::net::SocketAddr;

const TENANT: &str = "22222222-2222-2222-2222-222222222222";
const IDEMPOTENCY: &str = "01010101-0101-0101-0101-010101010101";

#[test]
fn tenant_service_requests_are_bounded_canonical_and_explicit() {
    let create = TenantCreateRequest::new(
        TENANT.to_owned(),
        "acme-observability".to_owned(),
        "Acme Observability".to_owned(),
        2_592_000,
        1,
        [1; 11],
        IDEMPOTENCY.to_owned(),
    );
    assert_eq!(
        TenantCreateRequest::decode(&create.encode().expect("encode")),
        Ok(create)
    );

    let display = TenantDisplayNameUpdateRequest::new(
        TENANT.to_owned(),
        1,
        "Acme Production".to_owned(),
        IDEMPOTENCY.to_owned(),
    );
    assert_eq!(
        TenantDisplayNameUpdateRequest::decode(&display.encode().expect("encode")),
        Ok(display)
    );
    assert!(
        TenantInspectRequest::new(TENANT.to_owned())
            .validate()
            .is_ok()
    );

    for body in [
        br#"{"tenant":"not-a-tenant","slug":"acme","display_name":"Acme","retention_seconds":1,"weight":1,"memory_bytes":1,"queue_slots":1,"task_slots":1,"buffer_cache_bytes":1,"batch_items":1,"lease_slots":1,"retry_slots":1,"io_permits":1,"cpu_work_units":1,"file_descriptors":1,"disk_headroom_bytes":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#.as_slice(),
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","expected_display_generation":0,"display_name":"Acme","idempotency_key":"01010101-0101-0101-0101-010101010101"}"#.as_slice(),
    ] {
        assert!(TenantCreateRequest::decode(body).is_err() || TenantDisplayNameUpdateRequest::decode(body).is_err());
    }
}

#[test]
fn tenant_descriptor_exposes_only_redacted_administration_metadata() {
    let descriptor = TenantDescriptor::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","slug":"acme-observability","display_name":"Acme Observability","retention_seconds":2592000,"display_generation":1,"retention_generation":1,"lifecycle":"active"}"#,
    )
    .expect("checked descriptor");
    assert_eq!(descriptor.lifecycle, TenantLifecycleState::Active);
    assert!(TenantDescriptor::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","slug":"acme-observability","display_name":"Acme","retention_seconds":0,"display_generation":1,"retention_generation":1,"lifecycle":"active"}"#,
    )
    .is_err());
}

#[test]
fn tenant_list_pages_have_a_rendered_response_bound() {
    let descriptor = TenantDescriptor {
        tenant: "22222222-2222-2222-2222-222222222222".to_owned(),
        slug: "a".repeat(63),
        // This permitted 128-byte value combines UTF-8 and JSON escaping.
        display_name: format!("{}😀", "\0".repeat(124)),
        retention_seconds: u64::MAX,
        display_generation: u64::MAX,
        retention_generation: u64::MAX,
        lifecycle: TenantLifecycleState::Suspended,
    };
    let page = TenantListResponse {
        tenants: vec![descriptor.clone(); 48],
        continuation: Some("ab".repeat(42)),
    };
    assert!(page.encode().expect("bounded page").len() <= MAX_RESPONSE_BYTES);
    assert!(
        TenantListResponse {
            tenants: vec![descriptor; 49],
            continuation: None,
        }
        .encode()
        .is_err()
    );
}

#[test]
fn tenant_registry_contract_artifacts_describe_each_served_route() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("canonical OpenAPI document");

    for (path, rpc, request, response) in [
        (
            "/v1/tenants:create",
            "positron.v1.TenantService/Create",
            "TenantCreateRequest",
            "TenantCreateResponse",
        ),
        (
            "/v1/tenants:inspect",
            "positron.v1.TenantService/Inspect",
            "TenantInspectRequest",
            "TenantInspectResponse",
        ),
        (
            "/v1/tenants:list",
            "positron.v1.TenantService/List",
            "TenantListRequest",
            "TenantListResponse",
        ),
        (
            "/v1/tenants:update-display-name",
            "positron.v1.TenantService/UpdateDisplayName",
            "TenantDisplayNameUpdateRequest",
            "TenantDisplayNameUpdateResponse",
        ),
    ] {
        let route = mapping["mappings"]
            .as_array()
            .expect("mapping routes")
            .iter()
            .find(|route| route["path"] == path)
            .unwrap_or_else(|| panic!("tenant route `{path}`"));
        assert_eq!(route["rpc"], rpc);
        assert_eq!(route["authentication"], "Bearer SystemAdministration");
        assert_eq!(route["max_request_bytes"], 2048);
        assert_eq!(route["max_response_bytes"], 65536);

        let operation = &openapi["paths"][path]["post"];
        assert!(operation["security"].is_array(), "{path}");
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{request}")
        );
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{response}")
        );
    }
}

#[test]
fn tenant_service_client_requires_an_explicit_transport_profile() {
    let endpoint: SocketAddr = "127.0.0.1:1".parse().expect("loopback endpoint");
    assert!(TenantServiceClient::new(TenantServiceTransport::PlaintextOptOut { endpoint }).is_ok());
    assert!(
        TenantServiceClient::new(TenantServiceTransport::Tls {
            endpoint,
            server_name: "127.0.0.2".to_owned(),
            trust_file: "missing-ca.pem".into(),
        })
        .is_err()
    );
}

#[test]
fn tenant_service_client_maps_the_published_display_generation_conflict()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..length]);
        assert!(request.starts_with("POST /v1/tenants:update-display-name HTTP/1.1\r\n"));
        let body = r#"{"code":"stale_display_generation","display_generation":2,"semantic_diff":"display name changed"}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = TenantServiceClient::new(TenantServiceTransport::PlaintextOptOut { endpoint })?;
    assert_eq!(
        client
            .update_display_name(
                "credential-material",
                &TenantDisplayNameUpdateRequest::new(
                    TENANT.to_owned(),
                    1,
                    "Acme Production".to_owned(),
                    IDEMPOTENCY.to_owned(),
                ),
            )
            .expect_err("stale display generation"),
        TenantServiceClientFailure::StaleGeneration
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
