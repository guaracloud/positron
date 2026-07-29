//! Public contract tests for the canonical Positron v1 interface.

use positron_api::generated::{
    ApiErrorCode, ApiFailureSource, ApiVersion, Capability, CapabilityAvailability,
    CapabilityClient, CapabilityRequest, CapabilityService, CompletionState, DeprecationState,
    MAX_PUBLIC_REQUEST_BYTES, RetryClass, SafeDetail, SchemaDigest, Transport,
};

#[test]
fn v1_capability_statement_is_typed_and_bound_to_the_canonical_schema() {
    let response = CapabilityService::negotiate(CapabilityRequest::for_version(ApiVersion::V1));

    assert_eq!(ApiVersion::V1.major(), 1);
    assert_eq!(response.availability(), CapabilityAvailability::Implemented);
    assert_eq!(response.api_major(), ApiVersion::V1);
    assert_eq!(response.schema_digest(), SchemaDigest::canonical());
    assert_eq!(
        response.schema_digest().as_str(),
        include_str!("../../../api/positron/v1/schema.sha256").trim()
    );
    assert!(
        include_str!("../../../api/positron/v1/openapi.json")
            .contains(response.schema_digest().as_str())
    );
    assert!(
        include_str!("../../../api/positron/v1/http.json")
            .contains(response.schema_digest().as_str())
    );
}

#[test]
fn unsupported_api_versions_are_refused_with_a_stable_closed_outcome() -> Result<(), std::io::Error>
{
    let response = CapabilityService::negotiate(CapabilityRequest::unknown(
        2,
        Capability::CanonicalPublicInterface,
    ));
    let refusal = response
        .refusal()
        .ok_or_else(|| std::io::Error::other("unsupported versions return a refusal"))?;

    assert_eq!(refusal.code(), ApiErrorCode::UnsupportedApiVersion);
    assert_eq!(refusal.retry_class(), RetryClass::Never);
    assert_eq!(refusal.completion_state(), CompletionState::Rejected);
    assert_eq!(refusal.source(), ApiFailureSource::CapabilityNegotiation);
    assert_eq!(refusal.safe_detail(), SafeDetail::ApiMajorUnsupported);
    Ok(())
}

#[test]
fn capability_statement_exposes_every_closed_availability_without_placeholders() {
    let implemented = CapabilityService::negotiate(CapabilityRequest::for_capability(
        ApiVersion::V1,
        Capability::CanonicalPublicInterface,
    ));
    let unavailable = CapabilityService::negotiate(CapabilityRequest::for_capability(
        ApiVersion::V1,
        Capability::ReleaseOneQuery,
    ));
    let unsupported = CapabilityService::negotiate(CapabilityRequest::for_capability(
        ApiVersion::V1,
        Capability::Metrics,
    ));

    assert_eq!(
        implemented.availability(),
        CapabilityAvailability::Implemented
    );
    assert_eq!(
        unavailable.availability(),
        CapabilityAvailability::Unavailable
    );
    assert_eq!(
        unsupported.availability(),
        CapabilityAvailability::Unsupported
    );
    assert_eq!(implemented.deprecation(), DeprecationState::Current);
    assert_eq!(
        unavailable.refusal().map(|error| error.code()),
        Some(ApiErrorCode::CapabilityUnavailable)
    );
    assert_eq!(
        unsupported.refusal().map(|error| error.code()),
        Some(ApiErrorCode::CapabilityUnsupported)
    );
    assert_eq!(
        unavailable.refusal().map(|error| error.safe_detail()),
        Some(SafeDetail::CapabilityNotAvailable)
    );
    assert_eq!(
        unsupported.refusal().map(|error| error.safe_detail()),
        Some(SafeDetail::CapabilityNotSupported)
    );
    assert_eq!(
        unavailable.refusal().map(|error| error.retry_class()),
        Some(RetryClass::Never)
    );
}

#[test]
fn generated_grpc_and_http_clients_map_to_the_same_checked_outcome() -> Result<(), std::io::Error> {
    let request = CapabilityRequest::for_capability(ApiVersion::V1, Capability::ReleaseOneQuery);
    let grpc = CapabilityClient::encode(request, Transport::GrpcProtobuf)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let http = CapabilityClient::encode(request, Transport::HttpJson)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let grpc_response =
        CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, grpc.as_bytes())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let http_response =
        CapabilityService::decode_and_negotiate(Transport::HttpJson, http.as_bytes())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;

    assert_eq!(grpc.method(), "POST");
    assert_eq!(http.method(), "POST");
    assert_eq!(grpc.path(), "/positron.v1.CapabilityService/Negotiate");
    assert_eq!(http.path(), "/v1/capabilities:negotiate");
    assert_eq!(grpc_response, http_response);
    assert_eq!(
        grpc_response.availability(),
        CapabilityAvailability::Unavailable
    );
    Ok(())
}

#[test]
fn http_client_publishes_and_honors_its_single_buffer_encoding_bound() -> Result<(), std::io::Error>
{
    let bounds = CapabilityClient::encoding_bounds();
    let request = CapabilityRequest::unknown(u32::MAX, Capability::Metrics);
    let encoded = CapabilityClient::encode(request, Transport::HttpJson)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;

    assert_eq!(bounds.maximum_body_bytes(), MAX_PUBLIC_REQUEST_BYTES);
    assert_eq!(bounds.maximum_heap_buffers(), 1);
    assert_eq!(bounds.maximum_intermediate_heap_bytes(), 0);
    assert_eq!(bounds.maximum_full_body_copies(), 0);
    assert_eq!(
        encoded.as_bytes(),
        br#"{"api_major":4294967295,"capability":3}"#
    );
    assert!(encoded.as_bytes().len() <= bounds.maximum_body_bytes());
    Ok(())
}

#[test]
fn old_and_new_v1_requests_have_deterministic_additive_compatibility() -> Result<(), std::io::Error>
{
    let old_grpc_request = [0x08, 0x01];
    let old_grpc =
        CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, &old_grpc_request)
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let new_request =
        CapabilityRequest::for_capability(ApiVersion::V1, Capability::CanonicalPublicInterface);
    let encoded = CapabilityClient::encode(new_request, Transport::GrpcProtobuf)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let new_grpc =
        CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, encoded.as_bytes())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let old_http = CapabilityService::decode_and_negotiate(
        Transport::HttpJson,
        include_bytes!("fixtures/capability-v1-old-client.json"),
    )
    .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let new_http = CapabilityService::decode_and_negotiate(
        Transport::HttpJson,
        include_bytes!("fixtures/capability-v1-current-client.json"),
    )
    .map_err(|error| std::io::Error::other(format!("{error:?}")))?;

    assert_eq!(old_grpc, new_grpc);
    assert_eq!(old_grpc, old_http);
    assert_eq!(old_http, new_http);
    assert_eq!(old_grpc.schema_digest(), SchemaDigest::canonical());
    Ok(())
}

#[test]
fn maximum_api_major_round_trips_to_an_explicit_version_refusal() -> Result<(), std::io::Error> {
    let request = CapabilityRequest::unknown(u32::MAX, Capability::CanonicalPublicInterface);
    let encoded = CapabilityClient::encode(request, Transport::GrpcProtobuf)
        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let response =
        CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, encoded.as_bytes())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;

    assert_eq!(
        response.availability(),
        CapabilityAvailability::VersionIncompatible
    );
    assert_eq!(
        response.refusal().map(|error| error.code()),
        Some(ApiErrorCode::UnsupportedApiVersion)
    );
    Ok(())
}

#[test]
fn overflowing_terminal_u32_varints_fail_closed_before_negotiation() -> Result<(), std::io::Error> {
    let cases = [
        &[0x08, 0xff, 0xff, 0xff, 0xff, 0x10][..],
        &[0x08, 0x01, 0x10, 0x80, 0x80, 0x80, 0x80, 0x10][..],
    ];

    for bytes in cases {
        let result = CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, bytes);
        let error = result.err().ok_or_else(|| {
            std::io::Error::other("overflowing u32 varint negotiated successfully")
        })?;
        assert_eq!(error.code(), ApiErrorCode::MalformedRequest);
        assert_eq!(error.retry_class(), RetryClass::AfterInputCorrection);
        assert_eq!(error.completion_state(), CompletionState::Rejected);
        assert_eq!(error.source(), ApiFailureSource::GrpcDecode);
        assert_eq!(error.safe_detail(), SafeDetail::RequestMalformed);
    }
    Ok(())
}

#[test]
fn http_u32_values_require_canonical_integer_grammar() {
    for bytes in [
        &br#"{"api_major":+1}"#[..],
        &br#"{"api_major":01}"#[..],
        &br#"{"api_major":-1}"#[..],
        &br#"{"api_major": 1}"#[..],
        &br#"{"api_major":1 }"#[..],
        &br#"{"api_major":1e0}"#[..],
        &br#"{"api_major":1.0}"#[..],
        &br#"{"api_major":1,"capability":+1}"#[..],
        &br#"{"api_major":1,"capability":01}"#[..],
    ] {
        let result = CapabilityService::decode_and_negotiate(Transport::HttpJson, bytes);
        assert_eq!(
            result.map_err(|error| error.code()),
            Err(ApiErrorCode::MalformedRequest)
        );
    }

    for bytes in [
        &br#"{"api_major":0}"#[..],
        &br#"{"api_major":4294967295}"#[..],
    ] {
        let response = CapabilityService::decode_and_negotiate(Transport::HttpJson, bytes);
        assert_eq!(
            response.map(|value| value.availability()),
            Ok(CapabilityAvailability::VersionIncompatible)
        );
    }
    let zero_capability = CapabilityService::decode_and_negotiate(
        Transport::HttpJson,
        br#"{"api_major":1,"capability":0}"#,
    );
    assert_eq!(
        zero_capability.map(|value| value.availability()),
        Ok(CapabilityAvailability::Implemented)
    );
}

#[test]
fn malformed_oversized_and_unknown_wire_inputs_fail_closed() {
    let oversized = vec![0_u8; MAX_PUBLIC_REQUEST_BYTES + 1];
    let cases = [
        (
            Transport::GrpcProtobuf,
            &[0x08, 0x80][..],
            ApiErrorCode::MalformedRequest,
        ),
        (
            Transport::GrpcProtobuf,
            &[0x18, 0x01][..],
            ApiErrorCode::UnknownField,
        ),
        (
            Transport::GrpcProtobuf,
            &[0x08, 0x01, 0x08, 0x01][..],
            ApiErrorCode::MalformedRequest,
        ),
        (
            Transport::GrpcProtobuf,
            &[0x08, 0x80, 0x80, 0x80, 0x80, 0x80][..],
            ApiErrorCode::MalformedRequest,
        ),
        (
            Transport::HttpJson,
            br#"{"api_major":1"#,
            ApiErrorCode::MalformedRequest,
        ),
        (
            Transport::HttpJson,
            br#"{"api_major":1,"caller_secret":"do-not-reflect"}"#,
            ApiErrorCode::UnknownField,
        ),
        (
            Transport::HttpJson,
            br#"{"api_major":1,"api_major":1}"#,
            ApiErrorCode::MalformedRequest,
        ),
        (
            Transport::HttpJson,
            br#"{"api_major":"not-a-number"}"#,
            ApiErrorCode::MalformedRequest,
        ),
    ];

    for (transport, bytes, expected) in cases {
        let result = CapabilityService::decode_and_negotiate(transport, bytes);
        assert_eq!(result.map_err(|error| error.code()), Err(expected));
    }
    let result = CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, &oversized);
    assert_eq!(
        result.map_err(|error| error.code()),
        Err(ApiErrorCode::RequestTooLarge)
    );
}

#[test]
fn generated_artifacts_publish_matching_routes_schemas_errors_and_capabilities() {
    let proto = include_str!("../../../api/positron/v1/positron.proto");
    let openapi = include_str!("../../../api/positron/v1/openapi.json");
    let http = include_str!("../../../api/positron/v1/http.json");

    for token in [
        "CapabilityRequest",
        "CapabilityResponse",
        "api_major",
        "capability",
        "CAPABILITY_AVAILABILITY_IMPLEMENTED",
        "CAPABILITY_AVAILABILITY_UNAVAILABLE",
        "CAPABILITY_AVAILABILITY_UNSUPPORTED",
        "CAPABILITY_AVAILABILITY_VERSION_INCOMPATIBLE",
        "PUBLIC_ERROR_CODE_MALFORMED_REQUEST",
        "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE",
        "PUBLIC_ERROR_CODE_UNKNOWN_FIELD",
    ] {
        assert!(proto.contains(token), "protobuf source omitted `{token}`");
    }
    for token in [
        "/v1/capabilities:negotiate",
        "NegotiateCapabilityResponse",
        "CapabilityRequest",
        "CapabilityResponse",
        "IMPLEMENTED",
        "UNAVAILABLE",
        "UNSUPPORTED",
        "VERSION_INCOMPATIBLE",
        "MALFORMED_REQUEST",
        "REQUEST_TOO_LARGE",
        "UNKNOWN_FIELD",
    ] {
        assert!(openapi.contains(token), "OpenAPI omitted `{token}`");
    }
    for token in [
        "positron.v1.CapabilityService/Negotiate",
        "/v1/capabilities:negotiate",
        "\"unknown_fields\": \"reject\"",
        "\"max_request_bytes\": 64",
        "\"proto\": \"api_major\"",
        "\"proto\": \"capability\"",
    ] {
        assert!(http.contains(token), "HTTP mapping omitted `{token}`");
    }
}

#[test]
fn public_failures_expose_only_closed_safe_details() -> Result<(), std::io::Error> {
    let result = CapabilityService::decode_and_negotiate(
        Transport::HttpJson,
        include_bytes!("fixtures/capability-v1-unknown-field.json"),
    );
    let error = match result {
        Ok(response) => {
            return Err(std::io::Error::other(format!(
                "unknown fields produced a response: {response:?}"
            )));
        },
        Err(error) => error,
    };

    assert_eq!(error.safe_detail(), SafeDetail::FieldNotRecognized);
    assert_eq!(error.retry_class(), RetryClass::AfterInputCorrection);
    assert_eq!(error.completion_state(), CompletionState::Rejected);
    assert_eq!(error.source(), ApiFailureSource::HttpDecode);
    assert!(!format!("{error:?}").contains("do-not-reflect"));
    Ok(())
}
