use positron_api::api_keys::{ApiKeyRequest, KeyAction, KeyScope};

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
