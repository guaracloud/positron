use std::error::Error;
use std::sync::Arc;

use positron_domain::identity::Scope;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_ingest::{IngestPolicy, PolicyAction, PolicyRule};
use positron_kernel::{CatalogPublicationFault, with_catalog_publication_fault_after};
use positron_query::QueryBudget;
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, request};
use crate::BootstrapFailureCode;
#[test]
fn explicit_default_tenant_key_provisioning_uses_the_single_governance_authority()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let created = initialized.create_api_key_for_tenant(
        system,
        initialized.default_tenant_id(),
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x91; 16])?,
    )?;
    let secret = created
        .secret()
        .ok_or("default query credential")?
        .to_owned();
    drop(initialized);

    let reopened = fixture.reopen()?;
    reopened.attribute(
        PresentedCredential::parse(&secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    Ok(())
}

#[test]
fn secondary_tenant_key_lifecycle_is_replay_safe_and_reopens_bound_to_its_tenant()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x97; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("key-lifecycle-tenant")?,
            "Key lifecycle tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x98; 16])?,
    )?;
    let created = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::Query,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x99; 16])?,
    )?;
    let predecessor = created.principal_id();
    let predecessor_secret = created.secret().ok_or("secondary query secret")?.to_owned();
    let listed = initialized.list_api_keys_for_tenant(system, tenant)?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].principal_id(), predecessor);
    assert_eq!(listed[0].scope(), Scope::Query);
    assert!(listed[0].is_active());
    assert_eq!(listed[0].generation().get(), 2);
    let rotation_key = AdministrativeIdempotencyKey::new([0x9a; 16])?;
    let rotated = initialized.rotate_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(2)?,
        rotation_key,
    )?;
    let successor = rotated.principal_id();
    let successor_secret = rotated
        .secret()
        .ok_or("secondary successor secret")?
        .to_owned();
    let replay = initialized.rotate_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(2)?,
        rotation_key,
    )?;
    assert_eq!(replay.principal_id(), successor);
    assert!(
        replay.secret().is_none(),
        "replay must not redisplay a secret"
    );
    initialized.revoke_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0x9b; 16])?,
    )?;
    let replay_after_later_mutation = initialized.rotate_api_key_for_tenant(
        system,
        tenant,
        predecessor,
        ResourceGeneration::new(2)?,
        rotation_key,
    )?;
    assert_eq!(replay_after_later_mutation.principal_id(), successor);
    assert!(
        replay_after_later_mutation.secret().is_none(),
        "a terminal retry after a later mutation must not redisplay its secret"
    );
    drop(initialized);

    let reopened = fixture.reopen()?;
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let descriptors = reopened.list_api_keys_for_tenant(system, tenant)?;
    assert_eq!(descriptors.len(), 2);
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == predecessor
            && !descriptor.is_active()
            && descriptor.generation().get() == 4
    }));
    assert!(descriptors.iter().any(|descriptor| {
        descriptor.principal_id() == successor
            && descriptor.is_active()
            && descriptor.generation().get() == 4
    }));
    assert!(
        reopened
            .attribute(
                PresentedCredential::parse(&predecessor_secret)?,
                RequestedIntent::Query,
                CompatibilityHints::none(),
            )
            .is_err()
    );
    let context = reopened.attribute(
        PresentedCredential::parse(&successor_secret)?,
        RequestedIntent::Query,
        CompatibilityHints::none(),
    )?;
    assert_eq!(
        context.tenant_attribution().map(|value| value.tenant_id()),
        Some(tenant)
    );
    Ok(())
}

#[test]
fn secondary_tenant_uses_its_own_activated_policy_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, default_ingest, _, administrator_secret) =
        fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x92; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("policy-tenant")?,
            "Policy tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x93; 16])?,
    )?;
    let ingest = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::Ingest,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x94; 16])?,
    )?;
    let administration = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x95; 16])?,
    )?;
    let ingest = ingest
        .secret()
        .ok_or("tenant ingest credential")?
        .to_owned();
    let administration = administration
        .secret()
        .ok_or("tenant administration credential")?
        .to_owned();
    let actor = initialized.attribute(
        PresentedCredential::parse(&administration)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    services.activate_ingest_policy(
        actor,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x96; 16])?,
        IngestPolicy::compile(
            2,
            vec![PolicyRule::new(
                "reject-tenant",
                Vec::new(),
                PolicyAction::Reject,
            )?],
        )?,
    )?;
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("secondary-policy").encode_to_vec())?
            .permanently_rejected_records(),
        1,
        "the secondary tenant must use its own persisted reject policy"
    );
    assert_eq!(
        services
            .ingest_otlp_logs(&default_ingest, request("default-policy").encode_to_vec())?
            .accepted_records(),
        1,
        "the secondary policy must not affect the default tenant"
    );
    Ok(())
}

#[test]
fn secondary_tenant_administrator_updates_quotas_with_replay_reopen_and_fault_safety()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x88; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("quota-tenant")?,
            "Quota tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x89; 16])?,
    )?;
    let tenant_administration = initialized.create_api_key_for_tenant(
        system,
        tenant,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x8a; 16])?,
    )?;
    let tenant_administration_secret = tenant_administration
        .secret()
        .ok_or("tenant administration credential")?
        .to_owned();
    let actor = initialized.attribute(
        PresentedCredential::parse(&tenant_administration_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let first_key = AdministrativeIdempotencyKey::new([0x8b; 16])?;
    let first = initialized.update_tenant_quota(
        actor,
        tenant,
        ResourceGeneration::new(1)?,
        first_key,
        1,
        [1; 11],
    )?;
    assert_eq!(first.resource_generation().get(), 2);
    assert_eq!(
        initialized.update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(1)?,
            first_key,
            1,
            [1; 11],
        )?,
        first,
        "an exact secondary quota retry returns the original successor"
    );
    let conflict = initialized
        .update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(1)?,
            first_key,
            1,
            [2; 11],
        )
        .expect_err("a changed retry must not reuse a secondary quota receipt");
    assert_eq!(
        conflict.code(),
        BootstrapFailureCode::TenantQuotaIdempotencyConflict
    );
    let second = initialized.update_tenant_quota(
        actor,
        tenant,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x8c; 16])?,
        1,
        [3; 11],
    )?;
    assert_eq!(second.resource_generation().get(), 3);
    assert_eq!(
        initialized.update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(1)?,
            first_key,
            1,
            [1; 11],
        )?,
        first,
        "an old receipt must not restore an obsolete live or durable quota"
    );
    let stale = initialized
        .update_tenant_quota(
            actor,
            tenant,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0x8d; 16])?,
            1,
            [4; 11],
        )
        .expect_err("new secondary mutations require the current resource generation");
    assert_eq!(
        stale.code(),
        BootstrapFailureCode::TenantQuotaStaleGeneration
    );
    assert_eq!(
        stale
            .quota_generation_conflict()
            .map(ResourceGeneration::get),
        Some(3)
    );

    let publication =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_quota(
                actor,
                tenant,
                ResourceGeneration::new(3).expect("known valid generation"),
                AdministrativeIdempotencyKey::new([0x8e; 16]).expect("known valid key"),
                1,
                [1; 11],
            )
        })
        .expect_err("failed publication must leave the secondary quota unchanged");
    assert_eq!(publication.code(), BootstrapFailureCode::CatalogUnavailable);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let reopened_actor = reopened.attribute(
        PresentedCredential::parse(&tenant_administration_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let successor = reopened.update_tenant_quota(
        reopened_actor,
        tenant,
        ResourceGeneration::new(3)?,
        AdministrativeIdempotencyKey::new([0x8f; 16])?,
        1,
        [2; 11],
    )?;
    assert_eq!(successor.resource_generation().get(), 4);
    Ok(())
}

#[test]
fn tenant_bound_keys_serve_only_the_created_tenant_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, default_query, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x77; 16])?;
    initialized
        .create_tenant(
            system,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("serving-tenant")?,
                "Serving tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x78; 16])?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?;
    let ingest = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::Ingest,
            None,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x79; 16])?,
        )
        .map_err(|failure| format!("ingest key creation: {failure:?}"))?;
    let query = initialized
        .create_api_key_for_tenant(
            system,
            tenant,
            Scope::Query,
            None,
            ResourceGeneration::new(2)?,
            AdministrativeIdempotencyKey::new([0x7a; 16])?,
        )
        .map_err(|failure| format!("query key creation: {failure:?}"))?;
    let ingest = ingest
        .secret()
        .ok_or("created ingest credential")?
        .to_owned();
    let query = query.secret().ok_or("created query credential")?.to_owned();
    drop(initialized);

    let reopened = fixture
        .reopen()
        .map_err(|failure| format!("reopen: {failure:?}"))?;
    let services = ServiceHandle::new(Arc::clone(&reopened))
        .map_err(|failure| format!("service construction: {failure:?}"))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("created-tenant-only").encode_to_vec())
            .map_err(|failure| format!("tenant ingest: {failure:?}"))?
            .accepted_records(),
        1
    );
    let budget =
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?;
    assert_eq!(
        services.query_log_bodies(&query, "logs | range query_time 0 100 | limit 16", budget)?,
        ["created-tenant-only"]
    );
    let budget =
        QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?.with_cpu_work_units(15)?;
    assert!(
        services
            .query_log_bodies(
                &default_query,
                "logs | range query_time 0 100 | limit 16",
                budget
            )?
            .is_empty(),
        "the default tenant must not read newly created tenant data"
    );
    Ok(())
}
