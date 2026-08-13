use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};

use super::GovernanceAuditEntry;
use crate::{InitialGovernanceIntent, InitialTenantIntent};

fn audit_intent() -> Vec<u8> {
    InitialGovernanceIntent::create_tenant(
        InitialTenantIntent::new(
            [1; 16],
            TenantId::from_bytes([2; 16]).expect("tenant"),
            TenantSlug::parse_canonical("default").expect("slug"),
            "Default tenant",
            PrincipalId::from_bytes([3; 16]).expect("principal"),
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            vec![8; 64],
            vec![9; 48],
            1,
            1,
            1,
            [1; 11],
        )
        .expect("intent"),
    )
    .expect("governance")
    .into_parts()
    .1
}

#[test]
fn committed_initial_audit_has_typed_redacted_meaning() {
    let entry = GovernanceAuditEntry::decode_intent(7, &audit_intent()).expect("audit");
    assert_eq!(entry.position(), 7);
    assert_eq!(entry.principal_id().to_bytes(), [3; 16]);
    assert_eq!(entry.tenant_id().map(TenantId::to_bytes), Some([2; 16]));
    assert_eq!(entry.action(), "instance.initialize");
    assert_eq!(entry.outcome(), "succeeded");
}

#[test]
fn audit_decoder_rejects_truncation_corruption_and_trailing_data() {
    let intent = audit_intent();
    for length in [0, 7, 8, 24, 40, intent.len() - 1] {
        assert!(GovernanceAuditEntry::decode_intent(1, &intent[..length]).is_err());
    }
    let mut corrupt = intent.clone();
    corrupt[0] ^= 1;
    assert!(GovernanceAuditEntry::decode_intent(1, &corrupt).is_err());
    let mut trailing = intent;
    trailing.push(0);
    assert!(GovernanceAuditEntry::decode_intent(1, &trailing).is_err());
}
