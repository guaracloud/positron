use super::{
    BootstrapKeyCustody, BootstrapKeyFailure, BootstrapKeyIdentity, BootstrapObjectPurpose,
};
use crate::InstanceId;

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
