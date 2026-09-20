use std::error::Error;
use std::num::NonZeroU64;

use positron_domain::identity::Scope;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};

use super::schema_maintenance::Fixture;
use crate::BootstrapFailureCode;

#[test]
fn system_audit_retention_replays_an_immutable_receipt_after_successor_compaction_and_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let first_key = AdministrativeIdempotencyKey::new([0xd1; 16])?;
    let first = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        first_key,
    )?;
    assert_eq!(first.policy_generation(), ResourceGeneration::new(2)?);
    assert_eq!(first.retained_record_limit().get(), 2);
    let audit = initialized.governance_audit_for_test()?;
    let typed = audit
        .iter()
        .find(|entry| entry.position() == first.audit_position())
        .and_then(positron_governance::GovernanceAuditEntry::as_system_audit_retention_update)
        .ok_or("typed system audit-retention evidence")?;
    assert_eq!(typed.actor_id(), initialized.system_administrator_id());
    assert_eq!(typed.expected_generation(), ResourceGeneration::new(1)?);
    assert_eq!(typed.generation(), first.policy_generation());
    assert_eq!(typed.retained_record_limit(), 2);
    assert!(typed.request_digest().iter().any(|byte| *byte != 0));
    let conflict = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            first_key,
        )
        .expect_err("a changed request under A's key must conflict");
    assert_eq!(
        conflict.code(),
        BootstrapFailureCode::SystemAuditRetentionIdempotencyConflict
    );

    let successor = initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xd2; 16])?,
    )?;
    assert_eq!(successor.policy_generation(), ResourceGeneration::new(3)?);
    assert_eq!(initialized.governance_audit_for_test()?.len(), 1);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let generation_before = reopened.catalog_generation();
    assert_eq!(
        reopened.update_system_audit_retention(
            actor,
            NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            first_key,
        )?,
        first,
        "the original durable receipt remains authoritative after a newer policy and compaction"
    );
    assert_eq!(reopened.catalog_generation(), generation_before);
    assert_eq!(reopened.governance_audit_for_test()?.len(), 1);
    Ok(())
}

#[test]
fn system_audit_retention_rejects_tenant_data_plane_and_revoked_tenant_contexts()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest_secret, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let ingest = initialized.attribute(
        PresentedCredential::parse(&ingest_secret)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let denied = initialized
        .update_system_audit_retention(
            ingest,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd3; 16])?,
        )
        .expect_err("data-plane attribution must not update system retention");
    assert_eq!(
        denied.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );
    let system_generation = initialized
        .list_api_keys(system)?
        .into_iter()
        .find(|key| key.principal_id() == initialized.system_administrator_id())
        .map(positron_governance::ApiKeyDescriptor::generation)
        .ok_or("system administrator descriptor")?;

    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        system_generation,
        AdministrativeIdempotencyKey::new([0xd4; 16])?,
    )?;
    let tenant_secret = tenant_key
        .secret()
        .ok_or("tenant administrator secret")?
        .to_owned();
    let tenant = initialized.attribute(
        PresentedCredential::parse(&tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let denied = initialized
        .update_system_audit_retention(
            tenant,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd5; 16])?,
        )
        .expect_err("tenant administration must not update system retention");
    assert_eq!(
        denied.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );

    initialized.revoke_api_key(
        system,
        tenant_key.principal_id(),
        initialized
            .list_api_keys(system)?
            .into_iter()
            .find(|key| key.principal_id() == tenant_key.principal_id())
            .map(positron_governance::ApiKeyDescriptor::generation)
            .ok_or("current tenant administrator descriptor")?,
        AdministrativeIdempotencyKey::new([0xd6; 16])?,
    )?;
    let denied = initialized
        .update_system_audit_retention(
            tenant,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xd7; 16])?,
        )
        .expect_err("a revoked tenant context must fail closed");
    assert_eq!(
        denied.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );
    Ok(())
}

#[test]
fn committed_system_audit_retention_replay_finishes_interrupted_reclamation_after_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xd8; 16])?,
    )?;
    let key = AdministrativeIdempotencyKey::new([0xd9; 16])?;
    let retained_record_limit = NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?;
    let expected = ResourceGeneration::new(2)?;
    let interrupted =
        with_catalog_publication_fault_after(CatalogPublicationFault::ReclaimAudit, 0, || {
            initialized.update_system_audit_retention(actor, retained_record_limit, expected, key)
        })
        .expect_err("the durable receipt must survive an interrupted post-commit reclaim");
    assert_eq!(interrupted.code(), BootstrapFailureCode::CatalogUnavailable);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let replay = reopened.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(2)?,
        key,
    )?;
    assert_eq!(replay.policy_generation(), ResourceGeneration::new(3)?);
    assert_eq!(reopened.governance_audit_for_test()?.len(), 1);
    Ok(())
}
