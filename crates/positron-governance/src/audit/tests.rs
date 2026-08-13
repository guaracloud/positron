use positron_domain::identity::{PrincipalId, TenantId, TenantSlug};

use super::{CatalogRootRotationStage, GovernanceAuditEntry, InitializationAuditEntry};
use crate::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};

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
            PrincipalId::from_bytes([12; 16]).expect("ingest principal"),
            [13; 32],
            [14; 32],
            PrincipalId::from_bytes([15; 16]).expect("query principal"),
            [16; 32],
            [17; 32],
            [6; 32],
            [7; 32],
            vec![8; 64],
            vec![9; 48],
            1,
            1,
            1,
            [1; 11],
            InitialAuditContext::new(1_725_000_001, [11; 16], true).expect("audit context"),
        )
        .expect("intent"),
    )
    .expect("governance")
    .into_parts()
    .1
}

#[test]
fn committed_initial_audit_has_typed_redacted_meaning() {
    let entry = InitializationAuditEntry::decode_intent(7, &audit_intent()).expect("audit");
    assert_eq!(entry.position(), 7);
    assert_eq!(entry.principal_id().to_bytes(), [3; 16]);
    assert_eq!(entry.tenant_id().map(TenantId::to_bytes), Some([2; 16]));
    assert_eq!(entry.action(), "instance.initialize");
    assert_eq!(entry.outcome(), "succeeded");
    assert_eq!(entry.ingest_time_unix_seconds(), 1_725_000_001);
    assert_eq!(entry.target(), [1; 16]);
    assert_eq!(entry.request_id(), [11; 16]);
    assert_eq!(entry.metadata().initialization_mode(), "non-interactive");
    assert_eq!(entry.metadata().tenant_slug(), "default");
}

#[test]
fn audit_decoder_rejects_truncation_corruption_and_trailing_data() {
    let intent = audit_intent();
    for length in [0, 7, 8, 24, 40, intent.len() - 1] {
        assert!(InitializationAuditEntry::decode_intent(1, &intent[..length]).is_err());
    }
    let mut corrupt = intent.clone();
    corrupt[0] ^= 1;
    assert!(InitializationAuditEntry::decode_intent(1, &corrupt).is_err());
    let mut trailing = intent;
    trailing.push(0);
    assert!(InitializationAuditEntry::decode_intent(1, &trailing).is_err());

    for range in [8..16, 70..86, 96..112] {
        let mut zeroed = audit_intent();
        zeroed[range].fill(0);
        assert!(InitializationAuditEntry::decode_intent(1, &zeroed).is_err());
    }
    for (offset, value) in [(32, 2), (69, 2), (112, 2)] {
        let mut invalid_tag = audit_intent();
        invalid_tag[offset] = value;
        assert!(InitializationAuditEntry::decode_intent(1, &invalid_tag).is_err());
    }
    for meaning in [b"instance.initialize".as_slice(), b"succeeded"] {
        let mut unsupported = audit_intent();
        let offset = unsupported
            .windows(meaning.len())
            .position(|window| window == meaning)
            .expect("known meaning");
        unsupported[offset] ^= 1;
        assert!(InitializationAuditEntry::decode_intent(1, &unsupported).is_err());
    }
}

#[test]
fn audit_schema_router_returns_one_typed_redacted_rotation_entry_or_refuses() {
    let mut valid = b"catalog-root-rotation-v1\0completed\0".to_vec();
    valid.extend_from_slice(&[1; 16]);
    valid.extend_from_slice(&2_u64.to_be_bytes());
    valid.extend_from_slice(b"sensitive operator context");
    let entry = GovernanceAuditEntry::decode_fields(8, [3; 16], &valid).expect("rotation");
    let rotation = entry.as_catalog_root_rotation().expect("typed rotation");
    assert_eq!(entry.position(), 8);
    assert_eq!(rotation.stage(), CatalogRootRotationStage::Completed);
    assert_eq!(rotation.action(), "catalog.root-rotation.completed");
    assert_eq!(rotation.provider_key_reference(), [1; 16]);
    assert_eq!(rotation.key_epoch(), 2);
    assert_eq!(rotation.transaction_id(), [3; 16]);
    assert_eq!(rotation.outcome(), "committed");
    assert!(!format!("{entry:?} {entry}").contains("sensitive operator context"));

    for corrupt in [
        b"unknown-audit-v1\0completed\0".as_slice(),
        b"catalog-root-rotation-v1\0unknown\0".as_slice(),
        b"catalog-root-rotation-v1\0completed\0".as_slice(),
    ] {
        assert!(GovernanceAuditEntry::decode_fields(1, [1; 16], corrupt).is_err());
    }
    let mut zero_epoch = valid.clone();
    let epoch_start = b"catalog-root-rotation-v1\0completed\0".len() + 16;
    zero_epoch[epoch_start..epoch_start + 8].fill(0);
    assert!(GovernanceAuditEntry::decode_fields(1, [1; 16], &zero_epoch).is_err());
    let mut zero_provider = valid;
    zero_provider[epoch_start - 16..epoch_start].fill(0);
    assert!(GovernanceAuditEntry::decode_fields(1, [1; 16], &zero_provider).is_err());
}
