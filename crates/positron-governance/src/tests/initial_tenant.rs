use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};

use super::{
    GovernanceIntentFailure, InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent,
};

fn intent(
    display: &str,
    integrity: Vec<u8>,
) -> Result<InitialTenantIntent, GovernanceIntentFailure> {
    InitialTenantIntent::new(
        [1; 16],
        TenantId::from_bytes([2; 16]).expect("tenant"),
        TenantSlug::parse_canonical("default").expect("slug"),
        display,
        PrincipalId::from_bytes([3; 16]).expect("principal"),
        [4; 32],
        [5; 32],
        PrincipalId::from_bytes([12; 16]).expect("ingest principal"),
        [13; 32],
        [14; 32],
        [6; 32],
        [7; 32],
        integrity,
        vec![9; 48],
        2_592_000,
        1,
        1,
        [10; 11],
        InitialAuditContext::new(1_725_000_001, [11; 16], true)?,
    )
}

#[test]
fn tenant_creation_encodes_every_authority_and_closed_audit() {
    let (object, audit) = InitialGovernanceIntent::create_tenant(
        intent("Default tenant", vec![8; 64]).expect("valid intent"),
    )
    .expect("encodable intent")
    .into_parts();
    assert!(object.starts_with(b"POSGOV02"));
    assert!(object.windows(14).any(|bytes| bytes == b"Default tenant"));
    assert!(object.windows(48).any(|bytes| bytes == [9; 48]));
    assert!(
        audit
            .windows(19)
            .any(|bytes| bytes == b"instance.initialize")
    );
    assert!(audit.windows(16).any(|bytes| bytes == [11; 16]));
}

#[test]
fn tenant_creation_rejects_missing_authority_with_closed_diagnostics() {
    let failure = match intent("", vec![8]) {
        Ok(_) => panic!("display is mandatory"),
        Err(failure) => failure,
    };
    assert_eq!(failure.to_string(), "initial governance intent is invalid");

    let oversized = intent("Default", vec![8; u16::MAX as usize + 1])
        .expect("constructor accepts bounded-by-publication payload");
    assert!(InitialGovernanceIntent::create_tenant(oversized).is_err());
}
