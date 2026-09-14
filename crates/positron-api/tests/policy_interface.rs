use positron_api::policy::{
    HTTP_ACTIVATE_PATH, HTTP_DIFF_PATH, HTTP_EXPLAIN_PATH, HTTP_TEST_PATH, HTTP_VALIDATE_PATH,
    MAX_ACTIVATE_REQUEST_BYTES, MAX_DIFF_REQUEST_BYTES, MAX_TEST_REQUEST_BYTES,
    PolicyActivateRequest, PolicyActivateServiceClient, PolicyActivateServiceClientFailure,
    PolicyDiffRequest, PolicyDiffServiceClient, PolicyDiffServiceClientFailure,
    PolicyExplainRequest, PolicyExplainServiceClient, PolicyPreviewRequest,
    PolicyPreviewServiceClient, PolicyPreviewServiceClientFailure, PolicyPreviewTransport,
    PolicyTestRequest, PolicyTestServiceClient, PolicyTestServiceClientFailure,
};

#[test]
fn generated_policy_activate_client_posts_generation_checked_idempotent_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    assert_eq!(HTTP_ACTIVATE_PATH, "/v1/policies:activate");
    assert_eq!(
        PolicyActivateRequest::decode(
            br#"{"policy_json":"{}","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101","unknown":true}"#
        ),
        Err(PolicyActivateServiceClientFailure::InvalidRequest)
    );
    assert_eq!(
        PolicyActivateRequest::new(
            "p".repeat(MAX_ACTIVATE_REQUEST_BYTES),
            1,
            "01010101-0101-0101-0101-010101010101".to_owned(),
        )
        .validate(),
        Err(PolicyActivateServiceClientFailure::InvalidRequest)
    );

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..length]);
        assert!(request.starts_with("POST /v1/policies:activate HTTP/1.1\r\n"));
        assert!(request.contains("authorization: Bearer key-material"));
        assert!(request.contains(r#""policy_json":"{\"generation\":2,\"rules\":[]}""#));
        assert!(request.contains(r#""expected_generation":1"#));
        assert!(request.contains(r#""idempotency_key":"01010101-0101-0101-0101-010101010101""#));
        let body = r#"{"resource_generation":2,"policy_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","audit_position":7}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client =
        PolicyActivateServiceClient::new(PolicyPreviewTransport::PlaintextOptOut { endpoint })?;
    let response = client.activate(
        "key-material",
        &PolicyActivateRequest::new(
            "{\"generation\":2,\"rules\":[]}".to_owned(),
            1,
            "01010101-0101-0101-0101-010101010101".to_owned(),
        ),
    )?;
    assert_eq!(response.resource_generation, 2);
    assert_eq!(response.audit_position, 7);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn policy_activate_contract_artifacts_publish_generation_and_idempotency_boundaries() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json")).expect("mapping");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("OpenAPI");
    let route = mapping["mappings"]
        .as_array()
        .expect("routes")
        .iter()
        .find(|route| route["path"] == HTTP_ACTIVATE_PATH)
        .expect("activate route");
    assert_eq!(route["authentication"], "Bearer TenantAdministration");
    assert_eq!(route["max_request_bytes"], 65_536);
    assert_eq!(
        route["responses"]["409"],
        serde_json::json!(["stale_generation", "idempotency_conflict"])
    );
    let operation = &openapi["paths"][HTTP_ACTIVATE_PATH]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PolicyActivateResponse"
    );
    let request = openapi["components"]["schemas"]["PolicyActivateRequest"]["properties"]
        .as_object()
        .expect("activate request properties");
    assert_eq!(request.len(), 3);
    assert!(request.contains_key("idempotency_key"));
    let response = openapi["components"]["schemas"]["PolicyActivateResponse"]["properties"]
        .as_object()
        .expect("activate response properties");
    assert_eq!(response.len(), 3);
    assert!(response.contains_key("audit_position"));
}

#[test]
fn generated_policy_explain_client_posts_bounded_inputs_and_decodes_redacted_explanation()
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
        assert!(request.starts_with("POST /v1/policies:explain HTTP/1.1\r\n"));
        assert!(request.contains("authorization: Bearer key-material"));
        assert!(request.contains(r#""policy_json":"{\"generation\":8,\"rules\":[]}""#));
        assert!(request.contains(r#""candidate_json":"{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}""#));
        let body = r#"{"policy_generation":8,"policy_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","outcome":"accepted","explanation":"default policy accepted candidate"}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client =
        PolicyExplainServiceClient::new(PolicyPreviewTransport::PlaintextOptOut { endpoint })?;
    let response = client.explain(
        "key-material",
        &PolicyExplainRequest::new(
            "{\"generation\":8,\"rules\":[]}".to_owned(),
            "{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}".to_owned(),
        ),
    )?;
    assert_eq!(response.policy_generation, 8);
    assert_eq!(response.outcome, "accepted");
    assert_eq!(response.explanation, "default policy accepted candidate");
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn policy_explain_contract_artifacts_publish_a_bounded_redacted_operation() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json")).expect("mapping");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("OpenAPI");
    let route = mapping["mappings"]
        .as_array()
        .expect("routes")
        .iter()
        .find(|route| route["path"] == HTTP_EXPLAIN_PATH)
        .expect("explain route");
    assert_eq!(route["authentication"], "Bearer TenantAdministration");
    assert_eq!(route["max_request_bytes"], 65_536);
    assert_eq!(route["max_response_bytes"], 8_192);
    let operation = &openapi["paths"][HTTP_EXPLAIN_PATH]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PolicyExplainResponse"
    );
    let properties = openapi["components"]["schemas"]["PolicyExplainResponse"]["properties"]
        .as_object()
        .expect("explain properties");
    assert_eq!(properties.len(), 4);
    assert!(properties.contains_key("explanation"));
}

#[test]
fn generated_policy_diff_client_posts_bounded_policies_and_decodes_redacted_categories()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    assert_eq!(HTTP_DIFF_PATH, "/v1/policies:diff");
    assert_eq!(
        PolicyDiffRequest::decode(
            br#"{"before_policy_json":"{}","after_policy_json":"{}","unknown":true}"#
        ),
        Err(PolicyDiffServiceClientFailure::InvalidRequest)
    );
    assert_eq!(
        PolicyDiffRequest::new("p".repeat(MAX_DIFF_REQUEST_BYTES), "{}".to_owned()).validate(),
        Err(PolicyDiffServiceClientFailure::InvalidRequest)
    );

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = listener.local_addr()?;
    let server = thread::spawn(move || -> Result<(), std::io::Error> {
        let (mut stream, _) = listener.accept()?;
        let mut request = [0_u8; 4096];
        let length = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..length]);
        assert!(request.starts_with("POST /v1/policies:diff HTTP/1.1\r\n"));
        assert!(request.contains(r#""before_policy_json":"{\"generation\":1,\"rules\":[]}""#));
        assert!(request.contains(r#""after_policy_json":"{\"generation\":2,\"rules\":[]}""#));
        let body = r#"{"before_policy_generation":1,"before_policy_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","after_policy_generation":2,"after_policy_digest":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210","semantic_changes":["generation_changed"]}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client =
        PolicyDiffServiceClient::new(PolicyPreviewTransport::PlaintextOptOut { endpoint })?;
    let response = client.diff(
        "key-material",
        &PolicyDiffRequest::new(
            "{\"generation\":1,\"rules\":[]}".to_owned(),
            "{\"generation\":2,\"rules\":[]}".to_owned(),
        ),
    )?;
    assert_eq!(response.before_policy_generation, 1);
    assert_eq!(response.after_policy_generation, 2);
    assert_eq!(response.semantic_changes, vec!["generation_changed"]);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn policy_diff_contract_artifacts_expose_only_redacted_semantic_categories() {
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json")).expect("mapping");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("OpenAPI");
    let route = mapping["mappings"]
        .as_array()
        .expect("routes")
        .iter()
        .find(|route| route["path"] == HTTP_DIFF_PATH)
        .expect("diff route");
    assert_eq!(route["authentication"], "Bearer TenantAdministration");
    assert_eq!(route["max_request_bytes"], 65_536);
    assert_eq!(route["max_response_bytes"], 8_192);
    let operation = &openapi["paths"][HTTP_DIFF_PATH]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PolicyDiffResponse"
    );
    let properties = openapi["components"]["schemas"]["PolicyDiffResponse"]["properties"]
        .as_object()
        .expect("diff properties");
    assert_eq!(properties.len(), 5);
    assert!(properties.contains_key("semantic_changes"));
}

#[test]
fn canonical_policy_validate_request_is_bounded_and_rejects_unknown_fields() {
    let request =
        PolicyPreviewRequest::decode(br#"{"policy_json":"{\"generation\":1,\"rules\":[]}"}"#)
            .expect("checked policy candidate");
    assert_eq!(request.policy_json(), "{\"generation\":1,\"rules\":[]}");
    assert_eq!(HTTP_VALIDATE_PATH, "/v1/policies:validate");
    assert_eq!(
        PolicyPreviewRequest::decode(br#"{"policy_json":"{}","unknown":true}"#),
        Err(PolicyPreviewServiceClientFailure::InvalidRequest)
    );
}

#[test]
fn canonical_policy_test_request_rejects_unknown_and_over_limit_input_before_transport() {
    assert_eq!(
        PolicyTestRequest::decode(br#"{"policy_json":"{}","candidate_json":"{}","unknown":true}"#),
        Err(PolicyTestServiceClientFailure::InvalidRequest)
    );
    let request = PolicyTestRequest::new("p".repeat(MAX_TEST_REQUEST_BYTES), "{}".to_owned());
    assert_eq!(
        request.validate(),
        Err(PolicyTestServiceClientFailure::InvalidRequest)
    );
}

#[test]
fn generated_policy_preview_client_posts_the_bounded_candidate()
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
        assert!(request.starts_with("POST /v1/policies:validate HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer key-material\r\n")
        );
        assert!(request.contains(r#""policy_json":"{\"generation\":1,\"rules\":[]}""#));
        let body = r#"{"policy_generation":1,"policy_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","rule_count":0}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client =
        PolicyPreviewServiceClient::new(PolicyPreviewTransport::PlaintextOptOut { endpoint })?;
    let response = client.validate(
        "key-material",
        &PolicyPreviewRequest::new("{\"generation\":1,\"rules\":[]}".to_owned()),
    )?;
    assert_eq!(response.policy_generation, 1);
    assert_eq!(response.rule_count, 0);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn policy_validate_contract_artifacts_publish_only_the_redacted_preview_result() {
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
        .find(|route| route["path"] == HTTP_VALIDATE_PATH)
        .expect("policy route");
    assert_eq!(route["authentication"], "Bearer TenantAdministration");
    assert_eq!(route["max_request_bytes"], 65_536);
    assert_eq!(
        route["response_fields"]
            .as_array()
            .expect("response fields")
            .iter()
            .map(|field| field["json"].as_str().expect("field name"))
            .collect::<Vec<_>>(),
        ["policy_generation", "policy_digest", "rule_count"]
    );
    let operation = &openapi["paths"][HTTP_VALIDATE_PATH]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PolicyValidateResponse"
    );
    assert_eq!(
        openapi["components"]["schemas"]["PolicyValidateResponse"]["properties"]
            .as_object()
            .expect("preview properties")
            .len(),
        3
    );
}

#[test]
fn generated_policy_test_client_posts_both_bounded_inputs_and_decodes_only_the_summary()
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
        assert!(request.starts_with("POST /v1/policies:test HTTP/1.1\r\n"));
        assert!(request.contains("content-type: application/json"));
        assert!(request.contains(r#""policy_json":"{\"generation\":4,\"rules\":[]}""#));
        assert!(request.contains(r#""candidate_json":"{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}""#));
        let body = r#"{"policy_generation":4,"policy_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","accepted":true,"applied_rule_count":0}"#;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client =
        PolicyTestServiceClient::new(PolicyPreviewTransport::PlaintextOptOut { endpoint })?;
    let response = client.test(
        "key-material",
        &PolicyTestRequest::new(
            "{\"generation\":4,\"rules\":[]}".to_owned(),
            "{\"receiver\":\"otlp_http_json\",\"signal\":\"logs\",\"attributes\":[]}".to_owned(),
        ),
    )?;
    assert_eq!(response.policy_generation, 4);
    assert!(response.accepted);
    assert_eq!(response.applied_rule_count, 0);
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn policy_test_contract_artifacts_expose_only_the_redacted_outcome_summary() {
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
        .find(|route| route["path"] == HTTP_TEST_PATH)
        .expect("policy test route");
    assert_eq!(route["authentication"], "Bearer TenantAdministration");
    assert_eq!(route["max_request_bytes"], 65_536);
    assert_eq!(
        route["response_fields"]
            .as_array()
            .expect("response fields")
            .iter()
            .map(|field| field["json"].as_str().expect("field name"))
            .collect::<Vec<_>>(),
        [
            "policy_generation",
            "policy_digest",
            "accepted",
            "applied_rule_count"
        ]
    );
    let operation = &openapi["paths"][HTTP_TEST_PATH]["post"];
    assert!(operation["security"].is_array());
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/PolicyTestResponse"
    );
    assert_eq!(
        openapi["components"]["schemas"]["PolicyTestResponse"]["properties"]
            .as_object()
            .expect("test result properties")
            .len(),
        4
    );
}
