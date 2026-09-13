use positron_api::tenant_retention::{
    RetentionReclamation, RetentionScopeImpact, TenantRetentionPreviewRequest,
    TenantRetentionPreviewResponse, TenantRetentionServiceClient,
    TenantRetentionServiceClientFailure, TenantRetentionTransport, TenantRetentionUpdateRequest,
};

const TENANT: &str = "22222222-2222-2222-2222-222222222222";
const DIGEST: &str = "abababababababababababababababababababababababababababababababab";
const IDEMPOTENCY: &str = "01010101-0101-0101-0101-010101010101";

#[test]
fn retention_requests_are_bounded_and_bind_reductions_to_an_opaque_preview_digest() {
    let preview = TenantRetentionPreviewRequest::new(TENANT.to_owned(), 86_400);
    assert_eq!(
        TenantRetentionPreviewRequest::decode(&preview.encode().expect("encode preview")),
        Ok(preview)
    );

    let reduction = TenantRetentionUpdateRequest::new(
        TENANT.to_owned(),
        86_400,
        1,
        Some(DIGEST.to_owned()),
        IDEMPOTENCY.to_owned(),
    );
    assert_eq!(
        TenantRetentionUpdateRequest::decode(&reduction.encode().expect("encode reduction")),
        Ok(reduction)
    );
    assert!(
        TenantRetentionUpdateRequest::new(
            TENANT.to_owned(),
            2_592_000,
            1,
            Some(DIGEST.to_owned()),
            IDEMPOTENCY.to_owned(),
        )
        .validate()
        .is_ok()
    );
    assert!(TenantRetentionUpdateRequest::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","proposed_retention_seconds":0,"expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#,
    )
    .is_err());
    assert!(TenantRetentionUpdateRequest::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","proposed_retention_seconds":86400,"expected_generation":1,"confirmation_digest":"not-a-digest","idempotency_key":"01010101-0101-0101-0101-010101010101"}"#,
    )
    .is_err());
}

#[test]
fn retention_preview_is_redacted_generation_bound_evidence() {
    let response = TenantRetentionPreviewResponse {
        tenant: TENANT.to_owned(),
        retention_generation: 1,
        proposed_retention_seconds: 86_400,
        catalog_identity: DIGEST.to_owned(),
        catalog_generation: 7,
        confirmation_digest: DIGEST.to_owned(),
        scopes: vec![RetentionScopeImpact {
            signal: "logs".to_owned(),
            shard: 0,
            catalog_identity: DIGEST.to_owned(),
            catalog_generation: 7,
            evaluated_at_unix_nanos: 123,
            affected_start_unix_nanos: Some(4),
            affected_end_unix_nanos: Some(8),
            affected_bytes: 172,
            immediately_reclaimable_bytes: 0,
            deferred_active_segment_bytes: 205,
            deferred_mixed_sealed_segment_bytes: 0,
            earliest_reclamation: RetentionReclamation::BlockedByInProcessSnapshot,
            earliest_reclamation_unix_nanos: None,
        }],
    };
    assert_eq!(
        TenantRetentionPreviewResponse::decode(&response.encode().expect("encode response")),
        Ok(response)
    );
}

#[test]
fn retention_client_uses_the_canonical_routes_and_preserves_typed_stale_details()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<(), std::io::Error> {
        for (path, status, body) in [
            (
                "/v1/tenant-retention:preview",
                "200 OK",
                r#"{"tenant":"22222222-2222-2222-2222-222222222222","retention_generation":1,"proposed_retention_seconds":86400,"catalog_identity":"abababababababababababababababababababababababababababababababab","catalog_generation":7,"confirmation_digest":"abababababababababababababababababababababababababababababababab","scopes":[]}"#,
            ),
            (
                "/v1/tenant-retention:update",
                "409 Conflict",
                r#"{"code":"stale_generation","retention_generation":2,"semantic_diff":"retention_seconds"}"#,
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
                    .contains("authorization: bearer tenant-administrator\r\n")
            );
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
    let client =
        TenantRetentionServiceClient::new(TenantRetentionTransport::PlaintextOptOut { endpoint })?;
    let preview = client.preview(
        "tenant-administrator",
        &TenantRetentionPreviewRequest::new(TENANT.to_owned(), 86_400),
    )?;
    assert_eq!(preview.confirmation_digest, DIGEST);
    assert_eq!(
        client.update(
            "tenant-administrator",
            &TenantRetentionUpdateRequest::new(
                TENANT.to_owned(),
                86_400,
                1,
                Some(DIGEST.to_owned()),
                IDEMPOTENCY.to_owned(),
            ),
        ),
        Err(TenantRetentionServiceClientFailure::StaleGeneration {
            retention_generation: 2,
            semantic_diff: "retention_seconds".to_owned(),
        })
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn retention_contract_artifacts_describe_the_served_bounded_tenant_administration_route() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("canonical HTTP mapping");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("canonical OpenAPI document");
    for (path, rpc, request, response) in [
        (
            "/v1/tenant-retention:preview",
            "positron.v1.TenantRetentionService/Preview",
            "TenantRetentionPreviewRequest",
            "TenantRetentionPreviewResponse",
        ),
        (
            "/v1/tenant-retention:update",
            "positron.v1.TenantRetentionService/Update",
            "TenantRetentionUpdateRequest",
            "TenantRetentionUpdateResponse",
        ),
    ] {
        let route = mapping["mappings"]
            .as_array()
            .expect("mapping routes")
            .iter()
            .find(|route| route["path"] == path)
            .expect("retention route");
        assert_eq!(route["rpc"], rpc);
        assert_eq!(route["request"], request);
        assert_eq!(route["response"], response);
        assert_eq!(route["authentication"], "Bearer TenantAdministration");
        assert_eq!(route["availability"], "available");
        assert_eq!(route["max_request_bytes"], 2048);
        assert_eq!(route["max_response_bytes"], 65536);
        assert_eq!(
            openapi["paths"][path]["post"]["x-positron-availability"],
            "available"
        );
    }
    assert!(
        openapi["components"]["schemas"]["TenantRetentionPreviewResponse"]["properties"]
            .get("confirmation_digest")
            .is_some()
    );
    assert!(
        openapi["components"]["schemas"]["TenantRetentionUpdateRequest"]["properties"]
            .get("confirmation_digest")
            .is_some()
    );
}
