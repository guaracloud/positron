use positron_domain::identity::TenantId;

use super::super::{SchemaSessionFailure, TenantSchemaRegistry};

#[test]
fn session_failures_have_one_bounded_public_diagnostic() {
    for failure in [
        SchemaSessionFailure::TenantConflict,
        SchemaSessionFailure::ReplayIntegrity,
        SchemaSessionFailure::RegistryLimitExceeded,
    ] {
        assert_eq!(failure.to_string(), "tenant schema session unavailable");
    }
}

#[test]
fn governed_registry_is_bounded_before_a_second_tenant_is_inserted() {
    let fixture = crate::tests::support::fixture().expect("fixture");
    let registry = TenantSchemaRegistry::new(1).expect("registry");
    let before = fixture
        .authority
        .governor()
        .inspect()
        .expect("before")
        .outstanding_total();
    let first = registry
        .session(fixture.tenant, fixture.authority.governor())
        .expect("first tenant");
    let checkpoint = first.checkpoint().expect("checkpoint");
    assert!(checkpoint.base_charge_bytes() > 0);
    assert!(
        fixture
            .authority
            .governor()
            .inspect()
            .expect("after")
            .outstanding_total()
            > before
    );

    let second = TenantId::from_bytes([3; 16]).expect("tenant");
    assert!(matches!(
        registry.session(second, fixture.authority.governor()),
        Err(SchemaSessionFailure::RegistryLimitExceeded)
    ));
    assert_eq!(
        first.checkpoint().expect("still held").base_charge_bytes(),
        checkpoint.base_charge_bytes()
    );
}

#[test]
fn governed_registry_sessions_are_structurally_tenant_isolated() {
    let first_tenant = TenantId::from_bytes([4; 16]).expect("tenant");
    let second_tenant = TenantId::from_bytes([5; 16]).expect("tenant");
    let first = crate::tests::support::fixture_for_tenant(first_tenant).expect("fixture");
    let second = crate::tests::support::fixture_for_tenant(second_tenant).expect("fixture");
    let registry = TenantSchemaRegistry::new(2).expect("registry");
    let first_session = registry
        .session(first_tenant, first.authority.governor())
        .expect("first session");
    let second_session = registry
        .session(second_tenant, second.authority.governor())
        .expect("second session");

    assert_eq!(
        first_session.checkpoint().expect("first").tenant(),
        first_tenant
    );
    assert_eq!(
        second_session.checkpoint().expect("second").tenant(),
        second_tenant
    );
    assert_eq!(first_session.checkpoint().expect("first").entry_count(), 0);
    assert_eq!(
        second_session.checkpoint().expect("second").entry_count(),
        0
    );
}
