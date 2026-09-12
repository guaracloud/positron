use positron_api::tenant_quotas::{
    TenantQuotaResources, TenantQuotaServiceClient, TenantQuotaTransport, TenantQuotaUpdateRequest,
};

#[test]
fn generated_tenant_quota_client_preserves_the_named_update_contract()
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
        assert!(request.starts_with("POST /v1/tenant-quotas:update HTTP/1.1\r\n"));
        assert!(request.contains("\"tenant\":\"22222222-2222-2222-2222-222222222222\""));
        assert!(request.contains("\"memory_bytes\":11"));
        assert!(request.contains("\"disk_headroom_bytes\":21"));
        assert!(request.contains("\"expected_generation\":1"));
        assert!(request.contains("\"idempotency_key\":\"01010101-0101-0101-0101-010101010101\""));
        let body = r#"{"resource_generation":2}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = TenantQuotaServiceClient::new(TenantQuotaTransport::PlaintextOptOut { endpoint })?;
    let response = client.update(
        "key-material",
        &TenantQuotaUpdateRequest::new(
            "22222222-2222-2222-2222-222222222222".to_owned(),
            1,
            "01010101-0101-0101-0101-010101010101".to_owned(),
            7,
            resources(11),
        ),
    )?;
    assert_eq!(response.resource_generation, 2);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn tenant_quota_request_rejects_zero_or_noncanonical_administration_inputs() {
    let endpoint = "192.0.2.1:8080".parse().expect("literal endpoint");
    let client = TenantQuotaServiceClient::new(TenantQuotaTransport::PlaintextOptOut { endpoint })
        .expect("explicit plaintext client");
    let invalid = TenantQuotaUpdateRequest::new(
        "not-a-tenant".to_owned(),
        0,
        "not-an-idempotency-key".to_owned(),
        0,
        TenantQuotaResources {
            memory_bytes: 0,
            ..resources(1)
        },
    );
    assert_eq!(
        client
            .update("key-material", &invalid)
            .expect_err("invalid input"),
        positron_api::tenant_quotas::TenantQuotaServiceClientFailure::InvalidRequest
    );
}

#[test]
fn tenant_quota_checked_decode_validates_once_and_exposes_all_runtime_parts() {
    let request = TenantQuotaUpdateRequest::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101","weight":7,"memory_bytes":11,"queue_slots":12,"task_slots":13,"buffer_cache_bytes":14,"batch_items":15,"lease_slots":16,"retry_slots":17,"io_permits":18,"cpu_work_units":19,"file_descriptors":20,"disk_headroom_bytes":21}"#,
    )
    .expect("checked quota request");
    assert_eq!(request.tenant(), "22222222-2222-2222-2222-222222222222");
    assert_eq!(request.expected_generation(), 1);
    assert_eq!(
        request.idempotency_key(),
        "01010101-0101-0101-0101-010101010101"
    );
    assert_eq!(request.weight(), 7);
    assert_eq!(request.resources(), resources(11));
    assert_eq!(
        request.resource_values(),
        [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
    );
    for body in [
        br#"{"tenant":"bad"}"#.as_slice(),
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101","weight":7,"memory_bytes":11,"queue_slots":12,"task_slots":13,"buffer_cache_bytes":14,"batch_items":15,"lease_slots":16,"retry_slots":17,"io_permits":18,"cpu_work_units":19,"file_descriptors":20,"disk_headroom_bytes":21,"unknown":1}"#.as_slice(),
        &vec![b' '; 1025],
    ] {
        assert!(TenantQuotaUpdateRequest::decode(body).is_err());
    }
}

#[test]
fn tenant_quota_client_preserves_only_published_failure_codes()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::tenant_quotas::TenantQuotaServiceClientFailure as Failure;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    fn request() -> TenantQuotaUpdateRequest {
        TenantQuotaUpdateRequest::new(
            "22222222-2222-2222-2222-222222222222".to_owned(),
            1,
            "01010101-0101-0101-0101-010101010101".to_owned(),
            1,
            resources(1),
        )
    }
    for (status, body, expected) in [
        (
            400,
            r#"{"code":"invalid_request"}"#,
            Failure::InvalidRequest,
        ),
        (
            401,
            r#"{"code":"authentication_rejected"}"#,
            Failure::AuthenticationRejected,
        ),
        (
            409,
            r#"{"code":"stale_generation","resource_generation":2,"semantic_diff":"quota generation changed"}"#,
            Failure::StaleGeneration {
                resource_generation: 2,
                semantic_diff: "quota generation changed".to_owned(),
            },
        ),
        (409, r#"{"code":"stale_generation"}"#, Failure::Transport),
        (
            409,
            r#"{"code":"idempotency_conflict"}"#,
            Failure::IdempotencyConflict,
        ),
        (
            503,
            r#"{"code":"administration_unavailable"}"#,
            Failure::AdministrationUnavailable,
        ),
        (404, r#"{"code":"unknown_tenant"}"#, Failure::Transport),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut s, _) = listener.accept()?;
            let mut b = [0; 4096];
            let _ = s.read(&mut b)?;
            s.write_all(format!("HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes())?;
            Ok(())
        });
        let client =
            TenantQuotaServiceClient::new(TenantQuotaTransport::PlaintextOptOut { endpoint })?;
        assert_eq!(
            client
                .update("key", &request())
                .expect_err("closed failure"),
            expected
        );
        server.join().map_err(|_| "panic")??;
    }
    Ok(())
}

#[test]
fn tenant_quota_contract_artifacts_publish_recoverable_stale_generation() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("HTTP mapping JSON");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("OpenAPI JSON");
    let route = mapping["mappings"]
        .as_array()
        .expect("mapping routes")
        .iter()
        .find(|route| route["path"] == positron_api::tenant_quotas::HTTP_PATH)
        .expect("quota route");
    assert_eq!(route["authentication"], "Bearer TenantAdministration");
    assert_eq!(route["max_request_bytes"], 1024);
    assert_eq!(
        route["stale_generation_response_fields"][0]["json"],
        "resource_generation"
    );
    assert_eq!(
        route["stale_generation_response_fields"][1]["json"],
        "semantic_diff"
    );
    let operation = &openapi["paths"][positron_api::tenant_quotas::HTTP_PATH]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/TenantQuotaUpdateResponse"
    );
    assert!(
        openapi["components"]["schemas"]["TenantQuotaFailure"]["oneOf"]
            .as_array()
            .is_some_and(|variants| variants.iter().any(|variant| {
                variant["required"]
                    .as_array()
                    .is_some_and(|required| required.iter().any(|field| field == "semantic_diff"))
            }))
    );
}

fn resources(start: u64) -> TenantQuotaResources {
    TenantQuotaResources {
        memory_bytes: start,
        queue_slots: start + 1,
        task_slots: start + 2,
        buffer_cache_bytes: start + 3,
        batch_items: start + 4,
        lease_slots: start + 5,
        retry_slots: start + 6,
        io_permits: start + 7,
        cpu_work_units: start + 8,
        file_descriptors: start + 9,
        disk_headroom_bytes: start + 10,
    }
}
