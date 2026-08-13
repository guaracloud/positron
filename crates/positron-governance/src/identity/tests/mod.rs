use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug};

use super::codec::decode_initial_identity;
use super::{
    AttributionFailure, AuthorizedContext, CompatibilityHints, PresentedCredential, RequestedIntent,
};
use crate::{InitialAuditContext, InitialGovernanceIntent, InitialTenantIntent};

fn encoded_identity() -> Vec<u8> {
    let intent = InitialTenantIntent::new(
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
        2_592_000,
        1,
        1,
        [10; 11],
        InitialAuditContext::new(1_725_000_001, [11; 16], true).expect("audit context"),
    )
    .expect("intent");
    InitialGovernanceIntent::create_tenant(intent)
        .expect("governance")
        .into_parts()
        .0
}

#[test]
fn initial_identity_decoder_reconstructs_closed_authority_and_reservations() {
    let identity = decode_initial_identity(&encoded_identity()).expect("identity");
    assert_eq!(identity.principal.to_bytes(), [3; 16]);
    assert_eq!(identity.tenant.to_bytes(), [2; 16]);
    assert_eq!(identity.tenant_slug.as_str(), "default");
    assert_eq!(identity.salt, [4; 32]);
    assert_eq!(identity.hash, [5; 32]);
    assert!(format!("{identity:?}").contains("Identity"));
    assert!(!Scope::SystemAdministration.is_tenant_scoped());
    assert_eq!(
        super::IdentityFailure.to_string(),
        "identity state is unavailable"
    );
}

#[test]
fn initial_identity_decoder_rejects_truncation_corruption_and_trailing_data() {
    let encoded = encoded_identity();
    for length in [0, 7, 8, 24, 40, encoded.len() - 1] {
        assert!(decode_initial_identity(&encoded[..length]).is_err());
    }
    let mut corrupt = encoded.clone();
    corrupt[0] ^= 1;
    assert!(decode_initial_identity(&corrupt).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_initial_identity(&trailing).is_err());

    for range in [8..24, 323..331, 343..351] {
        let mut zeroed = encoded_identity();
        zeroed[range].fill(0);
        assert!(decode_initial_identity(&zeroed).is_err());
    }
    let mut oversized_slug = encoded_identity();
    oversized_slug[40] = 64;
    assert!(decode_initial_identity(&oversized_slug).is_err());
    let mut missing_integrity = encoded_identity();
    missing_integrity[207..209].fill(0);
    assert!(decode_initial_identity(&missing_integrity).is_err());
    let mut empty_display = encoded_identity();
    empty_display.drain(49..63);
    empty_display[48] = 0;
    assert!(decode_initial_identity(&empty_display).is_err());
}

#[test]
fn credential_and_alias_parsers_are_bounded_canonical_and_redacted() {
    let encoded = format!("pos_{}", "ab".repeat(32));
    let credential = PresentedCredential::parse(&encoded).expect("credential");
    assert_eq!(credential.secret(), &[0xab; 32]);
    assert_eq!(
        format!("{credential:?}"),
        "PresentedCredential { <redacted> }"
    );
    let uppercase = format!("pos_{}", "A0".repeat(32));
    for rejected in ["", "pos_", "pos_00", uppercase.as_str()] {
        assert_eq!(
            PresentedCredential::parse(rejected)
                .expect_err("non-canonical credential")
                .to_string(),
            AttributionFailure.to_string()
        );
    }
    assert!(CompatibilityHints::external_tenant_alias("tenant_1.example").is_ok());
    let oversized = "a".repeat(129);
    for alias in ["", "bad alias", oversized.as_str()] {
        assert!(CompatibilityHints::external_tenant_alias(alias).is_err());
    }
    assert_eq!(CompatibilityHints::none().external_alias, None);
    assert_eq!(RequestedIntent::Query, RequestedIntent::Query);
}

#[test]
fn governance_inspection_rejects_forged_and_data_plane_contexts_with_one_shape() {
    let identity = decode_initial_identity(&encoded_identity()).expect("identity");
    let expected = AttributionFailure.to_string();
    for context in [
        AuthorizedContext {
            principal: identity.principal,
            scope: Scope::Ingest,
            tenant: Some(
                TenantAttribution::new(identity.principal, Scope::Ingest, identity.tenant)
                    .expect("tenant context"),
            ),
            authority: identity.instance,
        },
        AuthorizedContext {
            principal: identity.principal,
            scope: Scope::TenantAdministration,
            tenant: Some(
                TenantAttribution::new(
                    identity.principal,
                    Scope::TenantAdministration,
                    identity.tenant,
                )
                .expect("tenant-administration context"),
            ),
            authority: identity.instance,
        },
        AuthorizedContext {
            principal: identity.principal,
            scope: Scope::SystemAdministration,
            tenant: None,
            authority: [99; 16],
        },
        AuthorizedContext {
            principal: PrincipalId::from_bytes([99; 16]).expect("forged principal"),
            scope: Scope::SystemAdministration,
            tenant: None,
            authority: identity.instance,
        },
    ] {
        assert_eq!(
            identity
                .inspect(context, &[])
                .expect_err("invalid authority")
                .to_string(),
            expected
        );
    }
}
