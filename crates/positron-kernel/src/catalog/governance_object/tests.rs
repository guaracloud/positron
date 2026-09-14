//! Versioned governance-object codec regression tests.

#[cfg(feature = "test-support")]
use super::super::types::GovernanceFixtureObject;
use super::{CatalogFailureCode, CatalogGovernanceObject, CatalogGovernanceVersion};
use positron_domain::identity::ExternalTenantAlias;
use positron_domain::lifecycle::TenantLifecycleState;

#[test]
fn current_governance_object_requires_an_external_alias() {
    let encoded = valid_v4_object(false);
    let failure = match CatalogGovernanceObject::decode(&encoded) {
        Ok(_) => panic!("a current object without an alias must fail closed"),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
}

#[test]
fn released_governance_versions_preserve_actual_credentials_through_v6_successor() {
    for (version, expected_credentials) in [
        (CatalogGovernanceVersion::V1, 1_usize),
        (CatalogGovernanceVersion::V2, 2),
        (CatalogGovernanceVersion::V3, 3),
        (CatalogGovernanceVersion::V4, 3),
    ] {
        let legacy = legacy_object(version);
        let decoded = CatalogGovernanceObject::decode(&legacy)
            .expect("released governance record remains readable");
        assert_eq!(decoded.credentials().len(), expected_credentials);
        let expected = decoded.credentials().to_vec();
        let successor = decoded
            .with_credentials(2, &expected)
            .expect("first credential mutation canonically upgrades the record");
        assert!(successor.starts_with(b"POSGOV06"));
        let migrated = CatalogGovernanceObject::decode(&successor)
            .expect("canonical successor remains readable");
        assert_eq!(migrated.credential_generation(), 2);
        assert_eq!(migrated.lifecycle_generation(), 1);
        assert_eq!(migrated.credentials(), expected.as_slice());
    }
}

#[test]
fn v5_lifecycle_successor_preserves_credentials_and_advances_only_lifecycle_generation() {
    let mut v5 = valid_v4_object(true);
    v5[..8].copy_from_slice(b"POSGOV05");
    v5.extend_from_slice(&1_u64.to_be_bytes());
    v5.extend_from_slice(&3_u16.to_be_bytes());
    for (principal, scope) in [([3; 16], 4_u8), ([6; 16], 1), ([9; 16], 2)] {
        v5.extend_from_slice(&principal);
        v5.push(scope);
        v5.push(1);
        v5.extend_from_slice(&0_u64.to_be_bytes());
        v5.extend_from_slice(&[31; 32]);
        v5.extend_from_slice(&[32; 32]);
    }
    let decoded = CatalogGovernanceObject::decode(&v5).expect("v5 record remains readable");
    let credentials = decoded.credentials().to_vec();
    let successor = decoded
        .with_lifecycle(TenantLifecycleState::ReadOnly, 2)
        .expect("lifecycle successor encodes");
    assert!(successor.starts_with(b"POSGOV06"));
    let decoded = CatalogGovernanceObject::decode(&successor).expect("v6 record decodes");
    assert_eq!(decoded.lifecycle(), TenantLifecycleState::ReadOnly);
    assert_eq!(decoded.lifecycle_generation(), 2);
    assert_eq!(decoded.credential_generation(), 1);
    assert_eq!(decoded.credentials(), credentials.as_slice());
}

#[test]
fn v6_display_and_retention_successors_upgrade_independent_generations() {
    let mut v6 = valid_v4_object(true);
    v6[..8].copy_from_slice(b"POSGOV06");
    v6.extend_from_slice(&1_u64.to_be_bytes());
    v6.extend_from_slice(&1_u64.to_be_bytes());
    v6.extend_from_slice(&3_u16.to_be_bytes());
    for (principal, scope) in [([3; 16], 4_u8), ([6; 16], 1), ([9; 16], 2)] {
        v6.extend_from_slice(&principal);
        v6.push(scope);
        v6.push(1);
        v6.extend_from_slice(&0_u64.to_be_bytes());
        v6.extend_from_slice(&[7; 32]);
        v6.extend_from_slice(&[8; 32]);
    }
    let decoded = CatalogGovernanceObject::decode(&v6).expect("v6 record decodes");

    assert_eq!(decoded.display_generation(), 1);
    assert_eq!(decoded.retention_generation(), 1);
    let display = decoded
        .with_display_name("Renamed tenant", 2)
        .expect("display successor encodes");
    let display = CatalogGovernanceObject::decode(&display).expect("v7 display decodes");
    assert_eq!(display.display_name(), "Renamed tenant");
    assert_eq!(display.display_generation(), 2);
    assert_eq!(display.retention_generation(), 1);
    assert_eq!(display.tenant_key_envelope(), decoded.tenant_key_envelope());
    assert_eq!(display.quota_resources(), decoded.quota_resources());
    assert_eq!(
        display.lifecycle_generation(),
        decoded.lifecycle_generation()
    );

    let retention = display
        .with_retention_seconds(86_400, 2)
        .expect("retention successor encodes");
    let retention = CatalogGovernanceObject::decode(&retention).expect("v7 retention decodes");
    assert_eq!(retention.retention_seconds(), 86_400);
    assert_eq!(retention.display_generation(), 2);
    assert_eq!(retention.retention_generation(), 2);
    assert_eq!(
        retention.tenant_key_envelope(),
        decoded.tenant_key_envelope()
    );
    assert_eq!(retention.quota_resources(), decoded.quota_resources());
    assert_eq!(
        retention.lifecycle_generation(),
        decoded.lifecycle_generation()
    );

    let lifecycle = retention
        .with_lifecycle(TenantLifecycleState::ReadOnly, 2)
        .expect("v7 lifecycle successor encodes");
    let lifecycle = CatalogGovernanceObject::decode(&lifecycle).expect("v7 lifecycle decodes");
    assert_eq!(lifecycle.lifecycle(), TenantLifecycleState::ReadOnly);
    assert_eq!(lifecycle.lifecycle_generation(), 2);
    assert_eq!(lifecycle.display_generation(), 2);
    assert_eq!(lifecycle.retention_generation(), 2);
}

#[test]
fn v8_profile_successors_preserve_alias_and_remain_decodable() {
    let mut v6 = valid_v4_object(true);
    v6[..8].copy_from_slice(b"POSGOV06");
    v6.extend_from_slice(&1_u64.to_be_bytes());
    v6.extend_from_slice(&1_u64.to_be_bytes());
    v6.extend_from_slice(&3_u16.to_be_bytes());
    for (principal, scope) in [([3; 16], 4_u8), ([6; 16], 1), ([9; 16], 2)] {
        v6.extend_from_slice(&principal);
        v6.push(scope);
        v6.push(1);
        v6.extend_from_slice(&0_u64.to_be_bytes());
        v6.extend_from_slice(&[7; 32]);
        v6.extend_from_slice(&[8; 32]);
    }
    let alias =
        ExternalTenantAlias::parse("loki.retention-reopen").expect("canonical alias parses");
    let v8 = CatalogGovernanceObject::decode(&v6)
        .and_then(|record| record.with_display_name("Renamed tenant", 2))
        .and_then(|record| CatalogGovernanceObject::decode(&record))
        .and_then(|record| record.with_external_tenant_alias(alias.clone(), 2))
        .expect("alias successor encodes");
    let v8 = CatalogGovernanceObject::decode(&v8).expect("v8 record decodes");
    let expected_lifecycle = v8.lifecycle();
    let expected_lifecycle_generation = v8.lifecycle_generation();
    let expected_credential_generation = v8.credential_generation();
    let expected_credentials = v8.credentials().to_vec();
    let expected_envelope = v8.tenant_key_envelope().to_vec();
    let expected_quota = v8.quota_resources();

    let display = v8
        .with_display_name("Revised tenant", 3)
        .expect("display successor encodes");
    assert!(display.starts_with(b"POSGOV08"));
    let display = CatalogGovernanceObject::decode(&display).expect("v8 display successor decodes");
    assert_eq!(display.display_name(), "Revised tenant");
    assert_eq!(display.display_generation(), 3);
    assert_eq!(display.retention_generation(), 1);
    assert_eq!(display.external_tenant_alias(), Some(alias.clone()));
    assert_eq!(display.alias_generation(), 2);

    let successor = display
        .with_retention_seconds(86_400, 2)
        .expect("retention successor encodes");
    assert!(successor.starts_with(b"POSGOV08"));
    let successor =
        CatalogGovernanceObject::decode(&successor).expect("v8 retention successor decodes");
    assert_eq!(successor.retention_seconds(), 86_400);
    assert_eq!(successor.display_name(), "Revised tenant");
    assert_eq!(successor.display_generation(), 3);
    assert_eq!(successor.retention_generation(), 2);
    assert_eq!(successor.external_tenant_alias(), Some(alias));
    assert_eq!(successor.alias_generation(), 2);
    assert_eq!(successor.lifecycle(), expected_lifecycle);
    assert_eq!(
        successor.lifecycle_generation(),
        expected_lifecycle_generation
    );
    assert_eq!(
        successor.credential_generation(),
        expected_credential_generation
    );
    assert_eq!(successor.credentials(), expected_credentials.as_slice());
    assert_eq!(successor.tenant_key_envelope(), expected_envelope);
    assert_eq!(successor.quota_resources(), expected_quota);
}

#[cfg(feature = "test-support")]
#[test]
fn fixture_lifecycle_mutation_preserves_v7_v8_generations_and_alias_from_decoded_offsets() {
    let mut v6 = valid_v4_object(true);
    v6[..8].copy_from_slice(b"POSGOV06");
    v6.extend_from_slice(&1_u64.to_be_bytes());
    v6.extend_from_slice(&1_u64.to_be_bytes());
    v6.extend_from_slice(&3_u16.to_be_bytes());
    for (principal, scope) in [([3; 16], 4_u8), ([6; 16], 1), ([9; 16], 2)] {
        v6.extend_from_slice(&principal);
        v6.push(scope);
        v6.push(1);
        v6.extend_from_slice(&0_u64.to_be_bytes());
        v6.extend_from_slice(&[7; 32]);
        v6.extend_from_slice(&[8; 32]);
    }
    let v6 = CatalogGovernanceObject::decode(&v6).expect("v6 record decodes");
    let v7 = v6
        .with_display_name("Renamed tenant", 2)
        .and_then(|record| CatalogGovernanceObject::decode(&record))
        .and_then(|record| record.with_retention_seconds(86_400, 2))
        .expect("canonical v7 record encodes");
    let v7 = CatalogGovernanceObject::decode(&v7).expect("canonical v7 record decodes");
    let v7_alias = v7.external_tenant_alias();
    let v7_lifecycle = GovernanceFixtureObject::from_bytes(
        &v7.with_lifecycle(TenantLifecycleState::Active, v7.lifecycle_generation())
            .expect("v7 lifecycle record encodes"),
    )
    .expect("v7 fixture accepts canonical bytes")
    .with_lifecycle(TenantLifecycleState::ReadOnly)
    .expect("fixture locates v7 lifecycle through the decoder");
    let v7_lifecycle = CatalogGovernanceObject::decode(&v7_lifecycle.plaintext)
        .expect("fixture-mutated v7 record decodes");
    assert_eq!(v7_lifecycle.lifecycle(), TenantLifecycleState::ReadOnly);
    assert_eq!(v7_lifecycle.lifecycle_generation(), 1);
    assert_eq!(v7_lifecycle.display_generation(), 2);
    assert_eq!(v7_lifecycle.retention_generation(), 2);
    assert_eq!(v7_lifecycle.alias_generation(), 1);
    assert_eq!(v7_lifecycle.external_tenant_alias(), v7_alias);

    let alias = ExternalTenantAlias::parse("fixture.rebound").expect("valid external alias");
    let v8 = v7
        .with_external_tenant_alias(alias.clone(), 2)
        .expect("canonical v8 record encodes");
    let v8_lifecycle = GovernanceFixtureObject::from_bytes(&v8)
        .expect("v8 fixture accepts canonical bytes")
        .with_lifecycle(TenantLifecycleState::Suspended)
        .expect("fixture locates v8 lifecycle through the decoder");
    let v8_lifecycle = CatalogGovernanceObject::decode(&v8_lifecycle.plaintext)
        .expect("fixture-mutated v8 record decodes");
    assert_eq!(v8_lifecycle.lifecycle(), TenantLifecycleState::Suspended);
    assert_eq!(v8_lifecycle.lifecycle_generation(), 1);
    assert_eq!(v8_lifecycle.display_generation(), 2);
    assert_eq!(v8_lifecycle.retention_generation(), 2);
    assert_eq!(v8_lifecycle.alias_generation(), 2);
    assert_eq!(v8_lifecycle.external_tenant_alias(), Some(alias));

    let result = GovernanceFixtureObject::from_bytes(b"POSGOV08")
        .expect("bounded malformed fixture bytes are copyable")
        .with_lifecycle(TenantLifecycleState::ReadOnly);
    let failure = match result {
        Ok(_) => panic!("recognized governance prefixes require a canonical record"),
        Err(failure) => failure,
    };
    assert_eq!(failure.code(), CatalogFailureCode::IntegrityCorruption);
}

#[test]
fn v5_governance_object_accepts_a_bounded_scoped_credential_set() {
    let mut encoded = valid_v4_object(true);
    encoded[..8].copy_from_slice(b"POSGOV05");
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&3_u16.to_be_bytes());
    for (principal, scope) in [([3; 16], 4_u8), ([6; 16], 1), ([9; 16], 2)] {
        encoded.extend_from_slice(&principal);
        encoded.push(scope);
        encoded.push(1);
        encoded.extend_from_slice(&0_u64.to_be_bytes());
        encoded.extend_from_slice(&[31; 32]);
        encoded.extend_from_slice(&[32; 32]);
    }
    assert!(
        CatalogGovernanceObject::decode(&encoded).is_ok(),
        "v5 credential set must decode"
    );
}

fn legacy_object(version: CatalogGovernanceVersion) -> Vec<u8> {
    let mut encoded = valid_v4_object(true);
    if version == CatalogGovernanceVersion::V4 {
        encoded[..8].copy_from_slice(b"POSGOV04");
        return encoded;
    }
    let slug_length = usize::from(encoded[40]);
    let alias_start = 41 + slug_length;
    let alias_length = usize::from(encoded[alias_start + 1]);
    encoded.drain(alias_start..alias_start + 2 + alias_length);
    encoded[..8].copy_from_slice(b"POSGOV03");
    if version == CatalogGovernanceVersion::V3 {
        return encoded;
    }
    let display_length = usize::from(encoded[41 + slug_length]);
    let primary_end = 41 + slug_length + 1 + display_length + 80;
    encoded.drain(primary_end + 80..primary_end + 160);
    encoded[..8].copy_from_slice(b"POSGOV02");
    if version == CatalogGovernanceVersion::V2 {
        return encoded;
    }
    encoded.drain(primary_end..primary_end + 80);
    encoded[..8].copy_from_slice(b"POSGOV01");
    encoded
}

fn valid_v4_object(with_alias: bool) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"POSGOV04");
    encoded.extend_from_slice(&[1; 16]);
    encoded.extend_from_slice(&[2; 16]);
    encoded.push(7);
    encoded.extend_from_slice(b"default");
    encoded.push(u8::from(with_alias));
    if with_alias {
        encoded.push(14);
        encoded.extend_from_slice(b"trace-external");
    }
    encoded.push(7);
    encoded.extend_from_slice(b"Default");
    encoded.extend_from_slice(&[3; 16]);
    encoded.extend_from_slice(&[4; 32]);
    encoded.extend_from_slice(&[5; 32]);
    encoded.extend_from_slice(&[6; 16]);
    encoded.extend_from_slice(&[7; 32]);
    encoded.extend_from_slice(&[8; 32]);
    encoded.extend_from_slice(&[9; 16]);
    encoded.extend_from_slice(&[10; 32]);
    encoded.extend_from_slice(&[11; 32]);
    encoded.extend_from_slice(&[12; 32]);
    encoded.extend_from_slice(&[13; 32]);
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&[14; 2]);
    encoded.extend_from_slice(&2_u16.to_be_bytes());
    encoded.extend_from_slice(&[15; 2]);
    encoded.extend_from_slice(&2_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u64.to_be_bytes());
    encoded.extend_from_slice(&1_u32.to_be_bytes());
    for _ in 0..11 {
        encoded.extend_from_slice(&1_u64.to_be_bytes());
    }
    encoded.extend_from_slice(&[1, 4, 0, 1, 1]);
    encoded
}
