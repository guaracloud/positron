use positron_api::tenant_aliases::{
    TenantAliasBindRequest, TenantAliasBindResponse, TenantAliasServiceClient,
    TenantAliasServiceClientFailure, TenantAliasTransport,
};

const TENANT: &str = "22222222-2222-2222-2222-222222222222";
const IDEMPOTENCY: &str = "01010101-0101-0101-0101-010101010101";

#[test]
fn alias_binding_is_bounded_canonical_and_never_a_tenant_selector() {
    let request = TenantAliasBindRequest::new(
        TENANT.to_owned(),
        "loki.acme_42".to_owned(),
        1,
        IDEMPOTENCY.to_owned(),
    );
    assert!(request.validate().is_ok());
    assert_eq!(request.tenant(), TENANT);
    assert_eq!(request.external_alias(), "loki.acme_42");
    assert_eq!(
        TenantAliasBindRequest::decode(&request.encode().expect("encode")),
        Ok(request)
    );
    for body in [
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","external_alias":"bad alias","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#.as_slice(),
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","external_alias":"alias","expected_generation":0,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#.as_slice(),
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","external_alias":"alias","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101","tenant_hint":"forbidden"}"#.as_slice(),
    ] {
        assert!(TenantAliasBindRequest::decode(body).is_err());
    }
}

#[test]
fn alias_binding_response_is_a_redacted_audit_receipt() {
    let receipt = TenantAliasBindResponse::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","alias_generation":2,"audit_position":7,"audit_ingest_time_unix_seconds":9}"#,
    )
    .expect("receipt");
    assert_eq!(receipt.alias_generation, 2);
    assert!(TenantAliasBindResponse::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","alias_generation":0,"audit_position":7,"audit_ingest_time_unix_seconds":9}"#,
    )
    .is_err());
}

#[test]
fn alias_binding_contract_artifacts_require_system_administration_and_redact_the_alias() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("canonical OpenAPI document");
    let route = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["path"] == "/v1/tenant-aliases:bind")
        .expect("alias route");
    assert_eq!(route["rpc"], "positron.v1.TenantAliasService/Bind");
    assert_eq!(route["authentication"], "Bearer SystemAdministration");
    assert_eq!(route["max_request_bytes"], 1024);
    assert_eq!(route["max_response_bytes"], 1024);

    let operation = &openapi["paths"]["/v1/tenant-aliases:bind"]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/TenantAliasBindResponse"
    );
    let request = &openapi["components"]["schemas"]["TenantAliasBindRequest"];
    assert_eq!(
        request["properties"]
            .as_object()
            .expect("request fields")
            .len(),
        4
    );
    assert!(request["properties"].get("tenant_hint").is_none());
    let receipt = &openapi["components"]["schemas"]["TenantAliasBindResponse"];
    assert_eq!(
        receipt["properties"]
            .as_object()
            .expect("receipt fields")
            .len(),
        4
    );
    assert!(receipt["properties"].get("external_alias").is_none());
}

#[test]
fn generated_alias_client_binds_over_the_explicit_transport_and_keeps_the_receipt_redacted()
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
        assert!(request.starts_with("POST /v1/tenant-aliases:bind HTTP/1.1\r\n"));
        assert!(request.contains("authorization: Bearer credential-material\r\n"));
        assert!(request.contains("\"external_alias\":\"loki.acme_42\""));
        let body = r#"{"tenant":"22222222-2222-2222-2222-222222222222","alias_generation":2,"audit_position":7,"audit_ingest_time_unix_seconds":9}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = TenantAliasServiceClient::new(TenantAliasTransport::PlaintextOptOut { endpoint })?;
    let receipt = client.bind(
        "credential-material",
        &TenantAliasBindRequest::new(
            TENANT.to_owned(),
            "loki.acme_42".to_owned(),
            1,
            IDEMPOTENCY.to_owned(),
        ),
    )?;
    assert_eq!(receipt.alias_generation, 2);
    assert_eq!(receipt.audit_position, 7);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn generated_alias_client_preserves_published_conflict_and_authentication_failures()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    for (status, body, expected) in [
        (
            401,
            r#"{"code":"authentication_rejected"}"#,
            TenantAliasServiceClientFailure::AuthenticationRejected,
        ),
        (
            409,
            r#"{"code":"idempotency_conflict"}"#,
            TenantAliasServiceClientFailure::IdempotencyConflict,
        ),
        (
            409,
            r#"{"code":"alias_already_bound"}"#,
            TenantAliasServiceClientFailure::AliasAlreadyBound,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request)?;
            stream.write_all(format!("HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
            Ok(())
        });
        let client =
            TenantAliasServiceClient::new(TenantAliasTransport::PlaintextOptOut { endpoint })?;
        assert_eq!(
            client
                .bind(
                    "credential-material",
                    &TenantAliasBindRequest::new(
                        TENANT.to_owned(),
                        "loki.acme_42".to_owned(),
                        1,
                        IDEMPOTENCY.to_owned()
                    )
                )
                .expect_err("published failure"),
            expected
        );
        server.join().map_err(|_| "server panicked")??;
    }
    Ok(())
}
