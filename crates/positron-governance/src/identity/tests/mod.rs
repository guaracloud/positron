use positron_domain::identity::{PrincipalId, Scope, TenantAttribution, TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;

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
fn literal_v1_governance_identity_remains_readable() {
    let identity = decode_initial_identity(&literal_v1_identity()).expect("v1 identity");
    assert_eq!(identity.principal.to_bytes(), [3; 16]);
    assert_eq!(identity.tenant.to_bytes(), [2; 16]);
}

#[test]
fn literal_v2_governance_identity_remains_readable_without_query_authority() {
    let identity = decode_initial_identity(&literal_v2_identity()).expect("v2 identity");
    assert_eq!(identity.principal.to_bytes(), [3; 16]);
    assert_eq!(
        identity
            .ingest
            .as_ref()
            .map(|value| value.principal.to_bytes()),
        Some([12; 16])
    );
    assert!(identity.query.is_none());
}

#[test]
fn current_governance_identity_uses_v3_magic() {
    assert!(encoded_identity().starts_with(b"POSGOV03"));
}

#[test]
fn durable_lifecycle_states_are_decoded_and_query_readability_is_fail_closed() {
    for (encoding, expected, readable) in [
        (1, TenantLifecycleState::Active, true),
        (2, TenantLifecycleState::ReadOnly, true),
        (3, TenantLifecycleState::Suspended, false),
        (4, TenantLifecycleState::Purging, false),
        (5, TenantLifecycleState::Purged, false),
    ] {
        let mut encoded = encoded_identity();
        let lifecycle_byte = encoded.len().checked_sub(5).expect("lifecycle bytes");
        encoded[lifecycle_byte] = encoding;
        let identity = decode_initial_identity(&encoded).expect("lifecycle identity");
        assert_eq!(identity.lifecycle, expected);
        let tenant = TenantAttribution::new(
            identity.query.as_ref().expect("query authority").principal,
            Scope::Query,
            identity.tenant,
        )
        .expect("tenant attribution");
        let context = AuthorizedContext {
            principal: tenant.principal_id(),
            scope: Scope::Query,
            tenant: Some(tenant),
            authority: identity.instance,
            generation: identity.generation,
            lifecycle: expected,
        };
        assert_eq!(context.tenant_lifecycle(), expected);
        assert_eq!(identity.validate_query_context(context).is_ok(), readable);
    }
}

#[test]
fn unknown_or_layout_mismatched_governance_versions_fail_closed() {
    let mut unknown = literal_v1_identity();
    unknown[..8].copy_from_slice(b"POSGOV04");
    assert!(decode_initial_identity(&unknown).is_err());

    let mut mismatched = literal_v1_identity();
    mismatched[..8].copy_from_slice(b"POSGOV02");
    assert!(decode_initial_identity(&mismatched).is_err());
}

#[test]
fn distinct_ingest_principal_authenticates_without_system_impersonation() {
    let identity = decode_initial_identity(&encoded_identity()).expect("identity");
    let ingest = identity.ingest.as_ref().expect("ingest identity");
    assert_eq!(ingest.principal.to_bytes(), [12; 16]);
    assert_ne!(ingest.principal, identity.principal);
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

    for range in [8..24, 483..491, 503..511] {
        let mut zeroed = encoded_identity();
        zeroed[range].fill(0);
        assert!(decode_initial_identity(&zeroed).is_err());
    }
    let mut oversized_slug = encoded_identity();
    oversized_slug[40] = 64;
    assert!(decode_initial_identity(&oversized_slug).is_err());
    let mut missing_integrity = encoded_identity();
    missing_integrity[367..369].fill(0);
    assert!(decode_initial_identity(&missing_integrity).is_err());
    let mut empty_display = encoded_identity();
    empty_display.drain(49..63);
    empty_display[48] = 0;
    assert!(decode_initial_identity(&empty_display).is_err());
}

fn literal_v1_identity() -> Vec<u8> {
    let mut encoded = b"POSGOV01".to_vec();
    encoded.extend_from_slice(&[1; 16]);
    encoded.extend_from_slice(&[2; 16]);
    encoded.push(7);
    encoded.extend_from_slice(b"default");
    encoded.push(14);
    encoded.extend_from_slice(b"Default tenant");
    encoded.extend_from_slice(&[3; 16]);
    encoded.extend_from_slice(&[4; 32]);
    encoded.extend_from_slice(&[5; 32]);
    encoded.extend_from_slice(&[6; 32]);
    encoded.extend_from_slice(&[7; 32]);
    encoded.extend_from_slice(&64_u16.to_be_bytes());
    encoded.extend_from_slice(&[8; 64]);
    encoded.extend_from_slice(&48_u16.to_be_bytes());
    encoded.extend_from_slice(&[9; 48]);
    encoded.extend_from_slice(&2_592_000_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..11 {
        encoded.extend_from_slice(&10_u64.to_be_bytes());
    }
    encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
    encoded
}

fn literal_v2_identity() -> Vec<u8> {
    let mut encoded = literal_v1_identity();
    encoded[..8].copy_from_slice(b"POSGOV02");
    encoded.splice(
        143..143,
        [12; 16].into_iter().chain([13; 32]).chain([14; 32]),
    );
    encoded
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
            generation: 0,
            lifecycle: TenantLifecycleState::Active,
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
            generation: 0,
            lifecycle: TenantLifecycleState::Active,
        },
        AuthorizedContext {
            principal: identity.principal,
            scope: Scope::SystemAdministration,
            tenant: None,
            authority: [99; 16],
            generation: 0,
            lifecycle: TenantLifecycleState::Active,
        },
        AuthorizedContext {
            principal: PrincipalId::from_bytes([99; 16]).expect("forged principal"),
            scope: Scope::SystemAdministration,
            tenant: None,
            authority: identity.instance,
            generation: 0,
            lifecycle: TenantLifecycleState::Active,
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
