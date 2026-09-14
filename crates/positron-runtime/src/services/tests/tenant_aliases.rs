use std::error::Error;
use std::sync::Arc;

use positron_domain::identity::Scope;
use positron_domain::identity::{ExternalTenantAlias, TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    CatalogObject, CatalogProposal, CatalogPublicationFault, FormatEpoch, TransactionId,
    with_catalog_publication_fault_after,
};

use super::super::{ServiceFailure, ServiceHandle};
use super::schema_maintenance::{Fixture, open_catalog};
use crate::BootstrapFailureCode;

#[test]
fn ordinary_ingest_fails_closed_when_its_tenant_envelope_is_corrupt() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest, _) = fixture.initialized()?;
    corrupt_default_tenant_envelope(&initialized)?;
    assert!(
        matches!(
            ServiceHandle::new(Arc::clone(&initialized)),
            Err(ServiceFailure::KeyUnavailable)
        ),
        "ordinary services must not recover or admit data with a corrupt authenticated tenant envelope"
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest)?,
                RequestedIntent::Ingest,
                CompatibilityHints::none(),
            )
            .is_ok(),
        "envelope corruption is a key-custody failure, not a credential mutation"
    );
    Ok(())
}

#[test]
fn system_administrator_binds_an_immutable_alias_with_an_exact_replay() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let (initialized, ingest_secret, _, administrator_secret) = fixture.initialized_with_admin()?;
    let actor = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let alias = ExternalTenantAlias::parse("loki.compatibility_42")?;
    let bound = initialized.bind_tenant_alias(
        actor,
        initialized.default_tenant_id(),
        alias.clone(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xb1; 16])?,
    )?;
    assert_eq!(bound.alias_generation(), ResourceGeneration::new(2)?);
    assert_eq!(
        initialized.bind_tenant_alias(
            actor,
            initialized.default_tenant_id(),
            alias,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xb1; 16])?,
        )?,
        bound
    );
    assert_eq!(
        initialized
            .bind_tenant_alias(
                actor,
                initialized.default_tenant_id(),
                ExternalTenantAlias::parse("loki.rebind_forbidden")?,
                ResourceGeneration::new(2)?,
                AdministrativeIdempotencyKey::new([0xb2; 16])?,
            )
            .expect_err("an immutable alias must not be rebound")
            .code(),
        BootstrapFailureCode::TenantAliasAlreadyBound
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest_secret)?,
                RequestedIntent::Ingest,
                CompatibilityHints::external_tenant_alias("loki.compatibility_42")?,
            )
            .is_ok(),
        "the post-authentication compatibility assertion accepts the bound alias"
    );
    assert!(
        initialized
            .attribute(
                PresentedCredential::parse(&ingest_secret)?,
                RequestedIntent::Ingest,
                CompatibilityHints::external_tenant_alias("trace-external")?,
            )
            .is_err(),
        "the bootstrap alias cannot remain an alternate routing selector after a bind"
    );
    Ok(())
}

#[test]
fn tenant_aliases_are_unique_and_secondary_retries_are_exact_after_reopen()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xD1; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("alias-secondary")?,
            "Alias secondary",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xD1; 16])?,
    )?;
    let key = AdministrativeIdempotencyKey::new([0xD2; 16])?;
    let bound = initialized.bind_tenant_alias(
        system,
        tenant,
        ExternalTenantAlias::parse("loki.secondary")?,
        ResourceGeneration::new(1)?,
        key,
    )?;
    drop(initialized);
    let reopened = fixture.reopen()?;
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        reopened.bind_tenant_alias(
            system,
            tenant,
            ExternalTenantAlias::parse("loki.secondary")?,
            ResourceGeneration::new(1)?,
            key,
        )?,
        bound,
        "a reopen must retain the original exact idempotency receipt"
    );
    assert_eq!(
        reopened
            .bind_tenant_alias(
                system,
                tenant,
                ExternalTenantAlias::parse("loki.changed-body")?,
                ResourceGeneration::new(1)?,
                key,
            )
            .expect_err("same idempotency key with changed alias must conflict")
            .code(),
        BootstrapFailureCode::TenantAliasIdempotencyConflict
    );
    assert_eq!(
        reopened
            .bind_tenant_alias(
                system,
                reopened.default_tenant_id(),
                ExternalTenantAlias::parse("loki.secondary")?,
                ResourceGeneration::new(1)?,
                AdministrativeIdempotencyKey::new([0xD3; 16])?,
            )
            .expect_err("an alias cannot move across tenants")
            .code(),
        BootstrapFailureCode::TenantAliasConflict
    );
    Ok(())
}

#[test]
fn alias_publication_fault_leaves_no_audit_or_generation_successor() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let key = AdministrativeIdempotencyKey::new([0xD4; 16])?;
    let audit_count = initialized.governance_audit_for_test()?.len();
    let failed =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.bind_tenant_alias(
                system,
                initialized.default_tenant_id(),
                ExternalTenantAlias::parse("loki.atomic").expect("known alias"),
                ResourceGeneration::new(1).expect("known generation"),
                key,
            )
        })
        .expect_err("a pre-marker fault cannot publish alias state or audit evidence");
    assert_eq!(failed.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(initialized.governance_audit_for_test()?.len(), audit_count);
    let bound = initialized.bind_tenant_alias(
        system,
        initialized.default_tenant_id(),
        ExternalTenantAlias::parse("loki.atomic")?,
        ResourceGeneration::new(1)?,
        key,
    )?;
    assert_eq!(bound.alias_generation().get(), 2);
    assert_eq!(
        initialized.governance_audit_for_test()?.len(),
        audit_count + 1
    );
    Ok(())
}

#[test]
fn secondary_alias_is_only_a_post_authentication_compatibility_assertion()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xD5; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("alias-credential")?,
            "Alias credential",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xD5; 16])?,
    )?;
    initialized.bind_tenant_alias(
        system,
        tenant,
        ExternalTenantAlias::parse("loki.secondary-credential")?,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0xD6; 16])?,
    )?;
    let credential = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::Ingest,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0xD7; 16])?,
        )?
        .secret()
        .ok_or("secondary ingest credential")?
        .to_owned();
    let attributed = initialized.attribute(
        PresentedCredential::parse(&credential)?,
        RequestedIntent::Ingest,
        CompatibilityHints::external_tenant_alias("loki.secondary-credential")?,
    )?;
    assert_eq!(
        attributed
            .tenant_attribution()
            .map(|value| value.tenant_id()),
        Some(tenant)
    );
    for alias in ["loki.wrong-secondary", "trace-external"] {
        assert!(
            initialized
                .attribute(
                    PresentedCredential::parse(&credential)?,
                    RequestedIntent::Ingest,
                    CompatibilityHints::external_tenant_alias(alias)?,
                )
                .is_err(),
            "a compatibility hint cannot select or redirect the credential tenant"
        );
    }
    Ok(())
}

fn corrupt_default_tenant_envelope(
    initialized: &crate::InitializedInstance,
) -> Result<(), Box<dyn Error>> {
    let envelope = initialized
        .durable_identity()?
        .tenant_key_envelope(initialized.tenant)?
        .to_vec();
    let catalog = open_catalog(initialized)?;
    let snapshot = catalog.pin()?;
    let mut changed = false;
    let objects = snapshot
        .object_identities()
        .map(|identity| {
            let mut bytes = snapshot
                .object(identity)?
                .ok_or("missing catalog object")?
                .to_vec();
            if !changed
                && let Some(offset) = bytes
                    .windows(envelope.len())
                    .position(|candidate| candidate == envelope)
            {
                bytes[offset] ^= 0x01;
                changed = true;
            }
            CatalogObject::new(bytes).map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    assert!(
        changed,
        "the authenticated tenant envelope must be catalog-carried"
    );
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0xd2; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    Ok(())
}
