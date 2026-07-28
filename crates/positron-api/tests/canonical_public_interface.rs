//! Public contract tests for the canonical Positron v1 interface.

use positron_api::generated::{
    ApiErrorCode, ApiFailureSource, ApiVersion, CapabilityAvailability, CapabilityRequest,
    CapabilityService, CompletionState, RetryClass, SchemaDigest,
};

#[test]
fn v1_capability_statement_is_typed_and_bound_to_the_canonical_schema() {
    let response = CapabilityService::negotiate(CapabilityRequest::for_version(ApiVersion::V1));

    assert_eq!(ApiVersion::V1.major(), 1);
    assert_eq!(response.availability(), CapabilityAvailability::Implemented);
    assert_eq!(response.api_version(), ApiVersion::V1);
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
    let response = CapabilityService::negotiate(CapabilityRequest::unknown(2));
    let refusal = response
        .refusal()
        .ok_or_else(|| std::io::Error::other("unsupported versions return a refusal"))?;

    assert_eq!(refusal.code(), ApiErrorCode::UnsupportedApiVersion);
    assert_eq!(refusal.retry_class(), RetryClass::Never);
    assert_eq!(refusal.completion_state(), CompletionState::Rejected);
    assert_eq!(refusal.source(), ApiFailureSource::CapabilityNegotiation);
    Ok(())
}
