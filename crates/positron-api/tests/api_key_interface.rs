use positron_api::api_keys::{ApiKeyRequest, KeyAction, KeyScope};

#[test]
fn generated_api_key_service_client_uses_the_canonical_http_mapping()
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
        let request = &request[..length];
        let request = String::from_utf8_lossy(request);
        assert!(request.starts_with("POST /v1/api-keys:manage HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer key-material\r\n")
        );
        let body = "{\"keys\":[],\"principal\":\"11111111-1111-1111-1111-111111111111\"}";
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    });
    let client = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::PlaintextOptOut { endpoint },
    )?;
    let response = client.manage("key-material", &ApiKeyRequest::list())?;
    assert_eq!(
        response.principal.as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}

#[test]
fn generated_api_key_service_client_preserves_only_published_failure_codes()
-> Result<(), Box<dyn std::error::Error>> {
    use positron_api::api_keys::ApiKeyServiceClientFailure;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn failure(
        status: u16,
        body: &str,
    ) -> Result<ApiKeyServiceClientFailure, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let body = body.to_owned();
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request)?;
            stream.write_all(format!("HTTP/1.1 {status} Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())?;
            Ok(())
        });
        let failure = positron_api::api_keys::ApiKeyServiceClient::new(
            positron_api::api_keys::ApiKeyTransport::PlaintextOptOut { endpoint },
        )?
        .manage("key-material", &ApiKeyRequest::list())
        .expect_err("published failure must remain typed");
        server.join().map_err(|_| "server panicked")??;
        Ok(failure)
    }
    for (status, body, expected) in [
        (
            401,
            "{\"code\":\"authentication_rejected\"}",
            ApiKeyServiceClientFailure::AuthenticationRejected,
        ),
        (
            404,
            "{\"code\":\"key_unavailable\"}",
            ApiKeyServiceClientFailure::KeyUnavailable,
        ),
        (
            409,
            "{\"code\":\"stale_generation\"}",
            ApiKeyServiceClientFailure::StaleGeneration,
        ),
        (
            409,
            "{\"code\":\"idempotency_conflict\"}",
            ApiKeyServiceClientFailure::IdempotencyConflict,
        ),
        (
            503,
            "{\"code\":\"administration_unavailable\"}",
            ApiKeyServiceClientFailure::AdministrationUnavailable,
        ),
        (
            409,
            "{\"code\":\"key_unavailable\"}",
            ApiKeyServiceClientFailure::Transport,
        ),
        (
            500,
            "{\"detail\":\"secret-canary\"}",
            ApiKeyServiceClientFailure::Transport,
        ),
    ] {
        assert_eq!(failure(status, body)?, expected);
    }
    assert_ne!(
        failure(400, "{\"code\":\"invalid_request\"}")?,
        ApiKeyServiceClientFailure::Transport,
        "published invalid_request must not be erased into a transport failure"
    );
    assert_eq!(
        failure(
            503,
            &format!(
                "{{\"code\":\"administration_unavailable\",\"detail\":\"{}\"}}",
                "x".repeat(65_536)
            )
        )?,
        ApiKeyServiceClientFailure::Transport
    );
    Ok(())
}

#[test]
fn generated_client_refuses_remote_plaintext_before_request_construction() {
    let result = positron_api::api_keys::ApiKeyServiceClient::new(
        positron_api::api_keys::ApiKeyTransport::PlaintextOptOut {
            endpoint: "192.0.2.1:8080".parse().expect("literal socket address"),
        },
    );
    assert!(
        result.is_err(),
        "remote plaintext must be refused before a bearer is sent"
    );
}

#[test]
fn prost_generated_key_messages_share_the_http_contract() -> Result<(), Box<dyn std::error::Error>>
{
    use positron_api::api_keys::protobuf;
    use prost::Message;
    let request = protobuf::ApiKeyRequest {
        action: KeyAction::Create.into(),
        scope: Some(KeyScope::Query.into()),
        principal: None,
        expires_at_unix_seconds: None,
        expected_generation: Some(1),
        idempotency_key: Some("11111111-1111-1111-1111-111111111111".to_owned()),
    };
    let encoded = request.encode_to_vec();
    assert!(encoded.starts_with(&[8, 1, 16, 2, 40, 1, 50, 36]));
    let decoded = protobuf::ApiKeyRequest::decode(encoded.as_slice())?;
    assert_eq!(decoded, request);
    let http = serde_json::to_vec(&decoded)?;
    let checked = ApiKeyRequest::decode(&http)?;
    assert_eq!(checked.action(), KeyAction::Create);
    assert_eq!(checked.scope(), Some(KeyScope::Query));
    assert!(ApiKeyRequest::decode(br#"{"action":"unspecified"}"#).is_err());
    Ok(())
}

#[test]
fn key_contract_artifacts_publish_the_same_authenticated_route() {
    let proto = include_str!("../../../api/positron/v1/positron.proto");
    let mapping: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/http.json"))
            .expect("mapping JSON");
    let openapi: serde_json::Value =
        serde_json::from_str(include_str!("../../../api/positron/v1/openapi.json"))
            .expect("OpenAPI JSON");
    assert!(proto.contains("rpc Manage(ApiKeyRequest) returns (ApiKeyResponse)"));
    assert!(
        mapping["mappings"]
            .as_array()
            .expect("mappings")
            .iter()
            .any(|route| route["path"] == positron_api::api_keys::HTTP_PATH
                && route["max_request_bytes"] == 1024)
    );
    assert!(openapi["paths"][positron_api::api_keys::HTTP_PATH]["post"]["security"].is_array());
    assert_eq!(
        mapping["schema_digest"],
        positron_api::generated::SchemaDigest::canonical().as_str()
    );
    assert_eq!(
        openapi["info"]["x-positron-schema-digest"],
        mapping["schema_digest"]
    );
}

#[test]
fn key_request_checks_mutation_preconditions_and_response_redaction() {
    for body in [
        r#"{"action":"create","scope":"query"}"#,
        r#"{"action":"list","expected_generation":1}"#,
        r#"{"action":"scope_inspect"}"#,
        r#"{"action":"rotate","principal":"bad"}"#,
        r#"{"action":"list","expires_at_unix_seconds":1}"#,
        r#"{"action":"create","scope":"custom"}"#,
    ] {
        assert!(ApiKeyRequest::decode(body.as_bytes()).is_err());
    }
    assert!(ApiKeyRequest::mutation(KeyAction::List, String::new(), 1, String::new()).is_err());
    assert!(
        ApiKeyRequest::create(
            KeyScope::Ingest,
            Some(0),
            1,
            "11111111-1111-1111-1111-111111111111".to_owned()
        )
        .encode()
        .is_err()
    );
    let response = positron_api::api_keys::ApiKeyResponse {
        keys: Vec::new(),
        principal: None,
        secret: Some("never-debug-this".to_owned()),
    };
    assert!(!format!("{response:?}").contains("never-debug-this"));
    assert!(positron_api::api_keys::ApiKeyResponse::decode(&vec![0; 65537]).is_err());
    let encoded = response.encode().expect("response encodes");
    assert!(
        positron_api::api_keys::ApiKeyResponse::decode(&encoded)
            .expect("response decodes")
            .secret
            .is_some()
    );
}

#[test]
fn canonical_key_request_round_trips_and_rejects_ambient_authority() {
    let request = ApiKeyRequest::create(
        KeyScope::Query,
        None,
        1,
        "01010101-0101-0101-0101-010101010101".to_owned(),
    );
    let encoded = request.encode().expect("typed request encodes");
    assert_eq!(ApiKeyRequest::decode(&encoded).expect("decode"), request);
    assert_eq!(request.action(), KeyAction::Create);
    assert!(ApiKeyRequest::decode(br#"{"action":"list","tenant":"other"}"#).is_err());
    assert!(ApiKeyRequest::decode(br#"{"action":"list","action":"create"}"#).is_err());
    assert!(ApiKeyRequest::decode(&vec![b' '; 1025]).is_err());
}
