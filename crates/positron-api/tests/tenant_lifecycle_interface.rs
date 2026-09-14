use positron_api::tenant_lifecycle::{
    TenantLifecycleState, TenantLifecycleTransitionRequest, TenantLifecycleTransitionResponse,
};

const TENANT: &str = "22222222-2222-2222-2222-222222222222";
const IDEMPOTENCY: &str = "01010101-0101-0101-0101-010101010101";

#[test]
fn lifecycle_transition_request_requires_canonical_target_generation_and_idempotency() {
    let request = TenantLifecycleTransitionRequest::new(
        TENANT.to_owned(),
        TenantLifecycleState::ReadOnly,
        1,
        IDEMPOTENCY.to_owned(),
    );
    assert!(request.validate().is_ok());
    assert_eq!(request.tenant(), TENANT);
    assert_eq!(request.target(), TenantLifecycleState::ReadOnly);
    assert_eq!(request.expected_generation(), 1);
    assert_eq!(request.idempotency_key(), IDEMPOTENCY);
    let encoded = request.encode().expect("valid request encodes");
    assert_eq!(
        TenantLifecycleTransitionRequest::decode(&encoded).expect("request round trips"),
        request
    );

    for body in [
        br#"{"tenant":"not-a-tenant","target":"read_only","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#.as_slice(),
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","target":"read_only","expected_generation":0,"idempotency_key":"01010101-0101-0101-0101-010101010101"}"#.as_slice(),
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","target":"read_only","expected_generation":1,"idempotency_key":"01010101-0101-0101-0101-010101010101","unknown":true}"#.as_slice(),
    ] {
        assert!(TenantLifecycleTransitionRequest::decode(body).is_err());
    }
}

#[test]
fn lifecycle_transition_response_exposes_only_transition_audit_metadata() {
    let response = TenantLifecycleTransitionResponse::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","from":"active","to":"read_only","lifecycle_generation":2,"audit_position":7,"audit_ingest_time_unix_seconds":9}"#,
    )
    .expect("checked response");
    assert_eq!(response.from, TenantLifecycleState::Active);
    assert_eq!(response.to, TenantLifecycleState::ReadOnly);
    assert_eq!(response.lifecycle_generation, 2);
    assert!(TenantLifecycleTransitionResponse::decode(
        br#"{"tenant":"22222222-2222-2222-2222-222222222222","from":"active","to":"read_only","lifecycle_generation":0,"audit_position":7,"audit_ingest_time_unix_seconds":9}"#,
    )
    .is_err());
}
