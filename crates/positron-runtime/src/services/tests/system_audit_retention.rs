use std::error::Error;
use std::num::NonZeroU64;

use positron_domain::identity::{Scope, TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    CatalogObject, CatalogProposal, CatalogPublicationFault, FormatEpoch, TransactionId,
    with_catalog_publication_fault_after,
};

use super::schema_maintenance::{Fixture, open_catalog};
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
fn retained_governance_audit_history_verifies_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xda; 16])?,
    )?;
    drop(initialized);

    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    reopened.verify_governance_audit_history(actor, None)?;
    let history = reopened.inspect_governance_audit_history(actor)?;
    assert!(history.retention_anchor_position().is_some());
    assert_eq!(
        history.earliest_visible_position(),
        history
            .records()
            .first()
            .ok_or("retained audit record")?
            .position()
    );
    Ok(())
}

#[test]
fn retained_audit_verifier_accepts_the_prior_trusted_anchor_and_rejects_a_foreign_checkpoint()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let checkpoint = initialized.publish_governance_audit_checkpoint(actor)?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        actor,
        NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xde; 16])?,
    )?;
    drop(initialized);
    let reopened = fixture.reopen()?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    reopened.verify_governance_audit_history(actor, Some(&checkpoint))?;

    let foreign = Fixture::new()?;
    let (foreign_instance, _, _, foreign_secret) = foreign.initialized_with_admin()?;
    let foreign_actor = foreign_instance.attribute(
        PresentedCredential::parse(&foreign_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let foreign_checkpoint = foreign_instance.publish_governance_audit_checkpoint(foreign_actor)?;
    let actor = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let failure = reopened
        .verify_governance_audit_history(actor, Some(&foreign_checkpoint))
        .expect_err("a trusted checkpoint from another instance is rollback evidence");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    Ok(())
}

#[test]
fn system_audit_contexts_are_identity_generation_bound_but_survive_unrelated_catalog_changes()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let stale = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.create_api_key(
        stale,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe1; 16])?,
    )?;

    let rejected_reader = initialized
        .inspect_governance_audit_history(stale)
        .expect_err("a system context predating an identity successor cannot read audit history");
    assert_eq!(
        rejected_reader.code(),
        BootstrapFailureCode::ApiKeyUnauthorized
    );
    let rejected_retention = initialized
        .update_system_audit_retention(
            stale,
            NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xe2; 16])?,
        )
        .expect_err("a system context predating an identity successor cannot mutate retention");
    assert_eq!(
        rejected_retention.code(),
        BootstrapFailureCode::SystemAuditRetentionUnauthorized
    );

    let current = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_system_audit_retention(
        current,
        NonZeroU64::new(2).ok_or("nonzero retained audit-record limit")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe3; 16])?,
    )?;
    assert!(
        !initialized
            .inspect_governance_audit_history(current)?
            .records()
            .is_empty(),
        "a catalog-only audit-retention successor does not invalidate its identity context"
    );
    Ok(())
}

#[test]
fn tenant_audit_context_is_identity_generation_bound() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key_for_tenant(
        system,
        initialized.default_tenant_id(),
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xe4; 16])?,
    )?;
    let tenant_secret = tenant_key.secret().ok_or("tenant administrator secret")?;
    let stale_tenant = initialized.attribute(
        PresentedCredential::parse(tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.create_api_key(
        system,
        Scope::Query,
        None,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0xe5; 16])?,
    )?;

    let denied = initialized
        .inspect_governance_audit_history(stale_tenant)
        .expect_err("an active tenant credential still requires a current identity context");
    assert_eq!(denied.code(), BootstrapFailureCode::ApiKeyUnauthorized);
    let current_tenant = initialized.attribute(
        PresentedCredential::parse(tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    assert!(
        initialized
            .inspect_governance_audit_history(current_tenant)?
            .records()
            .iter()
            .all(|entry| entry.tenant_id() == Some(initialized.default_tenant_id()))
    );
    Ok(())
}

#[test]
fn public_audit_history_is_scoped_and_rejects_data_plane_contexts() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest_secret, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let foreign_tenant = TenantId::from_bytes([0xdc; 16])?;
    initialized.create_tenant(
        system,
        foreign_tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("audit-history-foreign")?,
            "Foreign audit tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xdc; 16])?,
    )?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    let tenant_key = initialized.create_api_key_for_tenant(
        system,
        initialized.default_tenant_id(),
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xdb; 16])?,
    )?;
    let tenant_secret = tenant_key.secret().ok_or("tenant administrator secret")?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let all = initialized.inspect_governance_audit_history(system)?;
    assert!(!all.records().is_empty());
    let tenant = initialized.attribute(
        PresentedCredential::parse(tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let scoped = initialized.inspect_governance_audit_history(tenant)?;
    assert!(
        scoped
            .records()
            .iter()
            .all(|entry| { entry.tenant_id() == Some(initialized.default_tenant_id()) })
    );
    assert!(scoped.records().len() <= all.records().len());

    initialized.revoke_api_key(
        system,
        tenant_key.principal_id(),
        initialized
            .list_api_keys(system)?
            .into_iter()
            .find(|key| key.principal_id() == tenant_key.principal_id())
            .map(positron_governance::ApiKeyDescriptor::generation)
            .ok_or("current tenant administrator descriptor")?,
        AdministrativeIdempotencyKey::new([0xdd; 16])?,
    )?;
    let revoked = initialized
        .inspect_governance_audit_history(tenant)
        .expect_err("a revoked administrative context cannot inspect audit history");
    assert_eq!(revoked.code(), BootstrapFailureCode::ApiKeyUnauthorized);

    let ingest = initialized.attribute(
        PresentedCredential::parse(&ingest_secret)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let denied = initialized
        .inspect_governance_audit_history(ingest)
        .expect_err("data-plane contexts cannot inspect governance audit history");
    assert_eq!(denied.code(), BootstrapFailureCode::ApiKeyUnauthorized);
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

#[test]
fn retention_rejects_a_mismatched_legacy_terminal_receipt_without_publishing()
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
        AdministrativeIdempotencyKey::new([0xe6; 16])?,
    )?;
    replace_system_retention_receipt_for_test(&initialized, false, [0xe7; 16])?;
    let generation_before = initialized.catalog_generation();
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xe8; 16])?,
        )
        .expect_err("a mismatched retained terminal result cannot authorize audit pruning");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn retention_rejects_duplicate_terminal_receipts_without_publishing() -> Result<(), Box<dyn Error>>
{
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
        AdministrativeIdempotencyKey::new([0xe9; 16])?,
    )?;
    replace_system_retention_receipt_for_test(&initialized, true, [0xea; 16])?;
    let generation_before = initialized.catalog_generation();
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0xeb; 16])?,
        )
        .expect_err("duplicate retained terminal results cannot authorize audit pruning");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn retention_capacity_refusal_does_not_publish_a_partial_successor() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    fill_catalog_to_object_limit_for_test(&initialized, [0xec; 16])?;
    let generation_before = initialized.catalog_generation();
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_system_audit_retention(
            actor,
            NonZeroU64::new(1).ok_or("nonzero retained audit-record limit")?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xed; 16])?,
        )
        .expect_err("a full catalog must refuse the entire retention successor before migration");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.catalog_generation(), generation_before);
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    Ok(())
}

fn replace_system_retention_receipt_for_test(
    initialized: &crate::InitializedInstance,
    retain_original: bool,
    transaction: [u8; 16],
) -> Result<(), Box<dyn Error>> {
    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let receipt = basis
        .object_identities()
        .find_map(|identity| {
            basis
                .object(identity)
                .ok()
                .flatten()
                .filter(|bytes| bytes.starts_with(b"POSARR01"))
                .map(|bytes| (identity, bytes.to_vec()))
        })
        .ok_or("system audit-retention receipt")?;
    let mut altered = receipt.1;
    let last = altered.last_mut().ok_or("nonempty terminal receipt")?;
    *last ^= 0x01;
    let mut objects = basis
        .object_identities()
        .filter(|identity| retain_original || *identity != receipt.0)
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "catalog object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.push(CatalogObject::new(altered)?);
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}

fn fill_catalog_to_object_limit_for_test(
    initialized: &crate::InitializedInstance,
    transaction: [u8; 16],
) -> Result<(), Box<dyn Error>> {
    const CATALOG_OBJECT_LIMIT: usize = 1_024;

    let catalog = open_catalog(initialized)?;
    let basis = catalog.pin()?;
    let mut objects = basis
        .object_identities()
        .map(|identity| {
            basis
                .object(identity)?
                .ok_or_else(|| "catalog object".into())
                .and_then(|bytes| CatalogObject::new(bytes.to_vec()).map_err(Into::into))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    objects.try_reserve_exact(CATALOG_OBJECT_LIMIT.saturating_sub(objects.len()))?;
    while objects.len() < CATALOG_OBJECT_LIMIT {
        let mut bytes = b"retention-capacity-fixture\0".to_vec();
        bytes.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        objects.push(CatalogObject::new(bytes)?);
    }
    catalog.commit(
        basis.identity(),
        CatalogProposal::new(
            TransactionId::new(transaction)?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
