//! Public contract tests for the canonical Positron v1 interface.

use positron_api::generated::{
    ApiErrorCode, ApiFailureSource, ApiVersion, Capability, CapabilityAvailability,
    CapabilityClient, CapabilityRequest, CapabilityService, CompletionState, DeprecationState,
    EncodedRequest, MAX_PUBLIC_REQUEST_BYTES, RetryClass, SafeDetail, SchemaDigest, Transport,
};
use std::hint::black_box;

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
fn every_generated_enum_value_preserves_its_public_number_and_deprecation_state() {
    for (value, number) in [
        (Capability::Unspecified, 0),
        (Capability::CanonicalPublicInterface, 1),
        (Capability::ReleaseOneQuery, 2),
        (Capability::Metrics, 3),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (CapabilityAvailability::Unspecified, 0),
        (CapabilityAvailability::Implemented, 1),
        (CapabilityAvailability::Unavailable, 2),
        (CapabilityAvailability::Unsupported, 3),
        (CapabilityAvailability::VersionIncompatible, 4),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (DeprecationState::Unspecified, 0),
        (DeprecationState::Current, 1),
        (DeprecationState::Deprecated, 2),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (RetryClass::Unspecified, 0),
        (RetryClass::Never, 1),
        (RetryClass::AfterBackoff, 2),
        (RetryClass::AfterInputCorrection, 3),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (CompletionState::Unspecified, 0),
        (CompletionState::Rejected, 1),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (ApiErrorCode::Unspecified, 0),
        (ApiErrorCode::UnsupportedApiVersion, 1),
        (ApiErrorCode::CapabilityUnavailable, 2),
        (ApiErrorCode::CapabilityUnsupported, 3),
        (ApiErrorCode::MalformedRequest, 4),
        (ApiErrorCode::RequestTooLarge, 5),
        (ApiErrorCode::UnknownField, 6),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (ApiFailureSource::Unspecified, 0),
        (ApiFailureSource::CapabilityNegotiation, 1),
        (ApiFailureSource::GrpcDecode, 2),
        (ApiFailureSource::HttpDecode, 3),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
    for (value, number) in [
        (SafeDetail::Unspecified, 0),
        (SafeDetail::ApiMajorUnsupported, 1),
        (SafeDetail::CapabilityNotAvailable, 2),
        (SafeDetail::CapabilityNotSupported, 3),
        (SafeDetail::RequestMalformed, 4),
        (SafeDetail::RequestLimitExceeded, 5),
        (SafeDetail::FieldNotRecognized, 6),
    ] {
        assert_eq!(value as u32, number);
        assert!(!black_box(value).is_deprecated());
    }
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
    let grpc = CapabilityClient::encode(request, Transport::GrpcProtobuf);
    let http = CapabilityClient::encode(request, Transport::HttpJson);
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
fn unspecified_capability_defaults_identically_across_public_transports()
-> Result<(), std::io::Error> {
    let request = CapabilityRequest::for_capability(ApiVersion::V1, Capability::Unspecified);
    let direct = CapabilityService::negotiate(request);
    let grpc = CapabilityClient::encode(request, Transport::GrpcProtobuf);
    let http = CapabilityClient::encode(request, Transport::HttpJson);
    let grpc_response =
        CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, grpc.as_bytes())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
    let http_response =
        CapabilityService::decode_and_negotiate(Transport::HttpJson, http.as_bytes())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;

    assert_eq!(
        grpc.as_bytes(),
        &[0x08, 0x01, 0x10, 0x00],
        "protobuf preserves the canonical zero enum value"
    );
    assert_eq!(
        http.as_bytes(),
        br#"{"api_major":1,"capability":0}"#,
        "JSON preserves the canonical zero enum value"
    );
    assert_eq!(direct, grpc_response);
    assert_eq!(grpc_response, http_response);
    assert_eq!(
        direct.capability(),
        Capability::CanonicalPublicInterface,
        "unspecified is the additive old-client default"
    );
    Ok(())
}

#[test]
fn every_typed_request_encodes_infallibly_within_the_published_bound() {
    for request in [
        CapabilityRequest::for_capability(ApiVersion::V1, Capability::Unspecified),
        CapabilityRequest::for_capability(ApiVersion::V1, Capability::CanonicalPublicInterface),
        CapabilityRequest::for_capability(ApiVersion::V1, Capability::ReleaseOneQuery),
        CapabilityRequest::for_capability(ApiVersion::V1, Capability::Metrics),
        CapabilityRequest::unknown(u32::MAX, Capability::Metrics),
    ] {
        let expected = CapabilityService::negotiate(request);
        let grpc: EncodedRequest = CapabilityClient::encode(request, Transport::GrpcProtobuf);
        let http: EncodedRequest = CapabilityClient::encode(request, Transport::HttpJson);

        assert!(grpc.as_bytes().len() <= MAX_PUBLIC_REQUEST_BYTES);
        assert!(http.as_bytes().len() <= MAX_PUBLIC_REQUEST_BYTES);
        assert_eq!(
            CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, grpc.as_bytes()),
            Ok(expected)
        );
        assert_eq!(
            CapabilityService::decode_and_negotiate(Transport::HttpJson, http.as_bytes()),
            Ok(expected)
        );
    }
}

#[test]
fn unknown_capability_values_have_transport_parity_and_closed_sources() -> Result<(), std::io::Error>
{
    for (transport, bytes, source) in [
        (
            Transport::GrpcProtobuf,
            &[0x08, 0x01, 0x10, 0x04][..],
            ApiFailureSource::GrpcDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{"api_major":1,"capability":4}"#[..],
            ApiFailureSource::HttpDecode,
        ),
    ] {
        let error = CapabilityService::decode_and_negotiate(transport, bytes)
            .err()
            .ok_or_else(|| std::io::Error::other("unknown capability negotiated successfully"))?;

        assert_eq!(error.code(), ApiErrorCode::CapabilityUnsupported);
        assert_eq!(error.retry_class(), RetryClass::Never);
        assert_eq!(error.completion_state(), CompletionState::Rejected);
        assert_eq!(error.source(), source);
        assert_eq!(error.safe_detail(), SafeDetail::CapabilityNotSupported);
    }
    Ok(())
}

#[test]
fn canonical_field_order_is_transport_independent() {
    let canonical = CapabilityService::negotiate(CapabilityRequest::for_version(ApiVersion::V1));
    let grpc =
        CapabilityService::decode_and_negotiate(Transport::GrpcProtobuf, &[0x10, 0x01, 0x08, 0x01]);
    let http = CapabilityService::decode_and_negotiate(
        Transport::HttpJson,
        b" \n{\"capability\":1,\"api_major\":1}\t",
    );

    assert_eq!(grpc, Ok(canonical));
    assert_eq!(http, Ok(canonical));
}

#[test]
fn http_client_publishes_and_honors_its_single_buffer_encoding_bound() -> Result<(), std::io::Error>
{
    let bounds = CapabilityClient::encoding_bounds();
    let request = CapabilityRequest::unknown(u32::MAX, Capability::Metrics);
    let encoded = CapabilityClient::encode(request, Transport::HttpJson);

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
    let encoded = CapabilityClient::encode(new_request, Transport::GrpcProtobuf);
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
    let encoded = CapabilityClient::encode(request, Transport::GrpcProtobuf);
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
fn malformed_transport_boundaries_preserve_closed_failure_context() -> Result<(), std::io::Error> {
    for (transport, bytes, source) in [
        (
            Transport::GrpcProtobuf,
            &[][..],
            ApiFailureSource::GrpcDecode,
        ),
        (
            Transport::GrpcProtobuf,
            &[0x10, 0x01][..],
            ApiFailureSource::GrpcDecode,
        ),
        (
            Transport::GrpcProtobuf,
            &[0x08, 0x01, 0x10, 0x01, 0x10, 0x02][..],
            ApiFailureSource::GrpcDecode,
        ),
        (
            Transport::GrpcProtobuf,
            &[0x08][..],
            ApiFailureSource::GrpcDecode,
        ),
        (
            Transport::HttpJson,
            &[0xff][..],
            ApiFailureSource::HttpDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{}"#[..],
            ApiFailureSource::HttpDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{"capability":1}"#[..],
            ApiFailureSource::HttpDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{"api_major":1,"capability":1,"capability":2}"#[..],
            ApiFailureSource::HttpDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{"api_major":4294967296}"#[..],
            ApiFailureSource::HttpDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{"api_major":1x}"#[..],
            ApiFailureSource::HttpDecode,
        ),
        (
            Transport::HttpJson,
            &br#"{"api_major":}"#[..],
            ApiFailureSource::HttpDecode,
        ),
    ] {
        let error = CapabilityService::decode_and_negotiate(transport, bytes)
            .err()
            .ok_or_else(|| std::io::Error::other("malformed request negotiated successfully"))?;

        assert_eq!(error.code(), ApiErrorCode::MalformedRequest);
        assert_eq!(error.retry_class(), RetryClass::AfterInputCorrection);
        assert_eq!(error.completion_state(), CompletionState::Rejected);
        assert_eq!(error.source(), source);
        assert_eq!(error.safe_detail(), SafeDetail::RequestMalformed);
    }
    Ok(())
}

#[test]
fn request_body_limit_is_inclusive_and_transport_specific() -> Result<(), std::io::Error> {
    let at_limit = [0_u8; MAX_PUBLIC_REQUEST_BYTES];
    let over_limit = [0_u8; MAX_PUBLIC_REQUEST_BYTES + 1];

    for (transport, source, within_limit_code) in [
        (
            Transport::GrpcProtobuf,
            ApiFailureSource::GrpcDecode,
            ApiErrorCode::UnknownField,
        ),
        (
            Transport::HttpJson,
            ApiFailureSource::HttpDecode,
            ApiErrorCode::MalformedRequest,
        ),
    ] {
        let within_limit = CapabilityService::decode_and_negotiate(transport, &at_limit)
            .err()
            .ok_or_else(|| {
                std::io::Error::other("invalid boundary body negotiated successfully")
            })?;
        let over = CapabilityService::decode_and_negotiate(transport, &over_limit)
            .err()
            .ok_or_else(|| std::io::Error::other("oversized body negotiated successfully"))?;

        assert_eq!(within_limit.code(), within_limit_code);
        assert_eq!(within_limit.source(), source);
        assert_eq!(over.code(), ApiErrorCode::RequestTooLarge);
        assert_eq!(over.retry_class(), RetryClass::AfterInputCorrection);
        assert_eq!(over.completion_state(), CompletionState::Rejected);
        assert_eq!(over.source(), source);
        assert_eq!(over.safe_detail(), SafeDetail::RequestLimitExceeded);
    }
    Ok(())
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
