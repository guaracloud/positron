use super::{
    BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity, BootstrapObjectPurpose,
};
use crate::InstanceId;
use positron_domain::identity::TenantId;

use super::test_support::SecurityRoot;

#[test]
fn bootstrap_envelopes_reject_empty_and_substituted_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let instance = InstanceId::new([1; 16])?;
    let other = InstanceId::new([2; 16])?;

    assert_eq!(format!("{key:?}"), "BootstrapKeyCustody { <redacted> }");
    assert_eq!(
        key.protect(instance, BootstrapObjectPurpose::Pending, b""),
        Err(BootstrapKeyFailure::InvalidInput)
    );
    let encoded = key.protect(instance, BootstrapObjectPurpose::Pending, b"pending")?;
    for opened in [
        key.open_object(other, BootstrapObjectPurpose::Pending, &encoded),
        key.open_object(instance, BootstrapObjectPurpose::Claim, &encoded),
    ] {
        assert_eq!(opened, Err(BootstrapKeyFailure::Authentication));
    }
    assert_eq!(
        BootstrapKeyCustody::routed_instance(BootstrapObjectPurpose::Claim, &encoded),
        Err(BootstrapKeyFailure::Authentication)
    );
    let mut bad_length = encoded.clone();
    bad_length[48] ^= 1;
    assert_eq!(
        key.open_object(instance, BootstrapObjectPurpose::Pending, &bad_length),
        Err(BootstrapKeyFailure::Authentication)
    );
    Ok(())
}

#[test]
fn bootstrap_identity_and_failure_diagnostics_are_closed() {
    assert_eq!(
        BootstrapKeyIdentity::from_parts([0; 16], [1; 32], 1),
        Err(BootstrapKeyFailure::InvalidInput)
    );
    assert_eq!(
        BootstrapKeyFailure::Authentication.to_string(),
        "instance bootstrap key operation failed"
    );
}

#[test]
fn opening_missing_local_custody_is_a_closed_failure() -> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    assert_eq!(
        BootstrapKeyCustody::open(&root.path).map(|_| ()),
        Err(BootstrapKeyFailure::Custody)
    );
    Ok(())
}

#[test]
fn tenant_kek_envelope_round_trips_only_for_its_bound_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let root = SecurityRoot::create()?;
    let instance = InstanceId::new([0x51; 16])?;
    let other_instance = InstanceId::new([0x52; 16])?;
    let tenant = TenantId::from_bytes([0x53; 16])?;
    let other_tenant = TenantId::from_bytes([0x54; 16])?;
    let key = BootstrapKeyCustody::initialize(&root.path)?;
    let envelope = key.provision_tenant_key_envelope(instance, tenant, [0x55; 16], 7)?;
    let distinct = key.provision_tenant_key_envelope(instance, tenant, [0x56; 16], 7)?;
    assert_ne!(
        envelope, distinct,
        "fresh tenant KEK provisions are opaque and distinct"
    );
    let opened = key.resolve_tenant_key_envelope(instance, tenant, &envelope)?;
    drop(key);

    let reopened = BootstrapKeyCustody::open(&root.path)?;
    let recovered = reopened.resolve_tenant_key_envelope(instance, tenant, &envelope)?;
    assert_eq!(opened.expose_to_backend(), recovered.expose_to_backend());
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(other_instance, tenant, &envelope),
        Err(BootstrapKeyFailure::Authentication)
    ));
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(instance, other_tenant, &envelope),
        Err(BootstrapKeyFailure::Authentication)
    ));
    let mut substituted_epoch = envelope.clone();
    substituted_epoch[31] ^= 1;
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(instance, tenant, &substituted_epoch),
        Err(BootstrapKeyFailure::Authentication)
    ));
    let mut substituted_key_id = envelope.clone();
    substituted_key_id[23] ^= 1;
    assert!(matches!(
        reopened.resolve_tenant_key_envelope(instance, tenant, &substituted_key_id),
        Err(BootstrapKeyFailure::Authentication)
    ));
    Ok(())
}
