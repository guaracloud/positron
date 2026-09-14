use std::error::Error;
use std::sync::Arc;

use positron_domain::identity::Scope;
use positron_domain::identity::{TenantId, TenantSlug};
use positron_domain::lifecycle::TenantLifecycleState;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration, TenantAdministration,
};
use positron_kernel::{CatalogPublicationFault, FormatEpoch, with_catalog_publication_fault_after};
use positron_query::QueryBudget;
use prost::Message;

use super::super::ServiceHandle;
use super::schema_maintenance::{Fixture, open_catalog, request};
use crate::BootstrapFailureCode;
#[test]
fn new_default_tenant_envelope_serves_data_after_reopen() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query) = fixture.initialized()?;
    assert!(
        initialized
            .durable_identity()?
            .tenant_key_envelope(initialized.tenant)?
            .starts_with(b"POSTKE01"),
        "new initial tenants must persist a provisioned tenant KEK envelope"
    );
    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("postke-reopen").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["postke-reopen"]
    );
    Ok(())
}

#[test]
fn system_administrator_inspects_default_and_provisioned_tenants_without_secret_material()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xA1; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("inspection-tenant")?,
            "Inspection tenant",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xA1; 16])?,
    )?;

    let listed = initialized.list_tenants(system)?;
    assert_eq!(listed.len(), 2);
    let inspection = initialized.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.slug(), "inspection-tenant");
    assert_eq!(inspection.display_name(), "Inspection tenant");
    assert_eq!(inspection.display_generation().get(), 1);
    assert_eq!(inspection.retention_generation().get(), 1);
    Ok(())
}

#[test]
fn system_administrator_updates_a_provisioned_tenant_display_name_idempotently()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0xB1; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("display-name-tenant")?,
            "Original display name",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0xB1; 16])?,
    )?;

    let key = AdministrativeIdempotencyKey::new([0xB2; 16])?;
    let updated = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Renamed tenant",
        key,
    )?;
    let replay = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Renamed tenant",
        key,
    )?;
    assert_eq!(updated, replay);
    assert_eq!(updated.resource_generation().get(), 2);

    let changed_retry = initialized
        .update_tenant_display_name(
            system,
            tenant,
            ResourceGeneration::new(1)?,
            "Changed retry",
            key,
        )
        .expect_err("a changed retry must not reuse the original display successor");
    assert_eq!(
        changed_retry.code(),
        BootstrapFailureCode::TenantDisplayNameIdempotencyConflict
    );

    let second = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(2)?,
        "Second display name",
        AdministrativeIdempotencyKey::new([0xB3; 16])?,
    )?;
    assert_eq!(second.resource_generation().get(), 3);
    let audit = initialized
        .governance_audit_for_test()?
        .into_iter()
        .find(|entry| entry.position() == updated.audit_position())
        .ok_or("display-name audit")?;
    let display_audit = audit
        .as_tenant_display_name_update()
        .ok_or("display-name audit meaning")?;
    assert_eq!(audit.action(), "tenant.display-name.update");
    assert_eq!(display_audit.tenant_id(), tenant);
    assert_eq!(display_audit.expected_generation().get(), 1);
    assert_eq!(display_audit.generation().get(), 2);
    assert_eq!(display_audit.idempotency_key(), key);
    assert!(
        display_audit.request_digest().iter().any(|byte| *byte != 0),
        "audit retains a digest instead of the display name"
    );
    assert_eq!(
        initialized.update_tenant_display_name(
            system,
            tenant,
            ResourceGeneration::new(1)?,
            "Renamed tenant",
            key,
        )?,
        updated,
        "an old exact retry returns its original result without restoring old state"
    );
    let stale = initialized
        .update_tenant_display_name(
            system,
            tenant,
            ResourceGeneration::new(2)?,
            "Stale name",
            AdministrativeIdempotencyKey::new([0xB4; 16])?,
        )
        .expect_err("new display mutations require the current display generation");
    assert_eq!(
        stale.code(),
        BootstrapFailureCode::TenantDisplayNameStaleGeneration
    );
    assert_eq!(
        stale
            .display_generation_conflict()
            .map(|conflict| conflict.current_generation().get()),
        Some(3)
    );
    assert_eq!(
        stale
            .display_generation_conflict()
            .map(positron_governance::TenantDisplayGenerationConflict::semantic_diff),
        Some("display_name")
    );
    let publication =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_display_name(
                system,
                tenant,
                ResourceGeneration::new(3).expect("known display generation"),
                "Faulted display name",
                AdministrativeIdempotencyKey::new([0xB5; 16]).expect("known idempotency key"),
            )
        })
        .expect_err("failed publication must leave the display name unchanged");
    assert_eq!(publication.code(), BootstrapFailureCode::CatalogUnavailable);

    let inspection = initialized.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.display_name(), "Second display name");
    assert_eq!(inspection.display_generation().get(), 3);
    assert_eq!(inspection.retention_seconds(), 2_592_000);
    assert_eq!(inspection.retention_generation().get(), 1);
    drop(initialized);

    let reopened = fixture.reopen()?;
    let system = reopened.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let inspection = reopened.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.display_name(), "Second display name");
    assert_eq!(inspection.display_generation().get(), 3);
    assert_eq!(inspection.retention_generation().get(), 1);
    Ok(())
}

#[test]
fn system_administrator_updates_default_tenant_display_without_changing_retention()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = initialized.default_tenant_id();
    let updated = initialized.update_tenant_display_name(
        system,
        tenant,
        ResourceGeneration::new(1)?,
        "Renamed default tenant",
        AdministrativeIdempotencyKey::new([0xB6; 16])?,
    )?;
    assert_eq!(updated.resource_generation().get(), 2);
    let inspection = initialized.inspect_tenant(system, tenant)?;
    assert_eq!(inspection.display_name(), "Renamed default tenant");
    assert_eq!(inspection.display_generation().get(), 2);
    assert_eq!(inspection.retention_generation().get(), 1);
    Ok(())
}

#[test]
fn fresh_instance_publishes_epoch_two_default_tenant_registry_before_serving()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, ingest, query, administrator_secret) = fixture.initialized_with_admin()?;
    assert_eq!(
        initialized.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2),
        "fresh initialization must never publish provisioned tenant state as Epoch 1"
    );
    let catalog = open_catalog(&initialized)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [initialized.default_tenant_id()],
        "the directory must contain the one default tenant state held by POSGOV"
    );
    drop((snapshot, catalog));

    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x71; 16])?,
    )?;
    let tenant_administrator = initialized.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.update_tenant_quota(
        tenant_administrator,
        initialized.default_tenant_id(),
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x72; 16])?,
        1,
        [
            32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
        ],
    )?;
    initialized.transition_tenant_lifecycle(
        system,
        initialized.default_tenant_id(),
        TenantLifecycleState::ReadOnly,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    )?;
    initialized.transition_tenant_lifecycle(
        system,
        initialized.default_tenant_id(),
        TenantLifecycleState::Active,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x74; 16])?,
    )?;

    let services = ServiceHandle::new(Arc::clone(&initialized))?;
    assert_eq!(
        services
            .ingest_otlp_logs(&ingest, request("fresh-epoch-two").encode_to_vec())?
            .accepted_records(),
        1
    );
    drop((services, initialized));

    let reopened = fixture.reopen()?;
    assert_eq!(
        reopened.catalog_format_epoch()?,
        Some(FormatEpoch::CATALOG_V2)
    );
    let catalog = open_catalog(&reopened)?;
    let snapshot = catalog.pin()?;
    assert_eq!(
        TenantAdministration::registered_tenant_ids(&snapshot)?,
        [reopened.default_tenant_id()]
    );
    drop((snapshot, catalog));
    let reconstructed_tenant_administrator = reopened.attribute(
        PresentedCredential::parse(tenant_key.secret().ok_or("tenant key")?)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    assert!(
        reconstructed_tenant_administrator
            .tenant_attribution()
            .is_some_and(|attribution| attribution.tenant_id() == reopened.default_tenant_id())
    );
    assert!(
        reopened
            .durable_identity()?
            .tenant_key_envelope(reopened.default_tenant_id())?
            .starts_with(b"POSTKE01")
    );
    let services = ServiceHandle::new(Arc::clone(&reopened))?;
    assert_eq!(
        services.query_log_bodies(
            &query,
            "logs | range query_time 0 100 | limit 16",
            QueryBudget::new(1_000_000, 100, 100, 1_000_000, 1_000_000, 10)?
                .with_cpu_work_units(15)?,
        )?,
        ["fresh-epoch-two"]
    );
    Ok(())
}

#[test]
fn created_tenant_reopens_with_its_authenticated_envelope() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x75; 16])?;
    initialized
        .create_tenant(
            system,
            tenant,
            positron_governance::TenantCreateConfiguration::new(
                TenantSlug::parse_canonical("envelope-tenant")?,
                "Envelope tenant",
                2_592_000,
                1,
                [
                    32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
                ],
            ),
            AdministrativeIdempotencyKey::new([0x76; 16])?,
        )
        .map_err(|failure| format!("tenant creation: {failure:?}"))?;
    drop(initialized);

    let reopened = fixture.reopen()?;
    assert!(
        reopened
            .durable_identity()?
            .tenant_key_envelope(tenant)?
            .starts_with(b"POSTKE01"),
        "a registered tenant must reconstruct its own authenticated data-protection envelope"
    );
    Ok(())
}

#[test]
fn tenant_creation_does_not_require_a_registry_generation_precondition()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let (initialized, _, _, administrator_secret) = fixture.initialized_with_admin()?;
    let system = initialized.attribute(
        PresentedCredential::parse(&administrator_secret)?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;

    let created = initialized.create_tenant(
        system,
        TenantId::from_bytes([0x74; 16])?,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("no-create-precondition")?,
            "No creation precondition",
            2_592_000,
            1,
            [
                32_000_000, 32, 32, 5_000_000, 2_048, 32, 32, 32, 32, 32, 2_000_000,
            ],
        ),
        AdministrativeIdempotencyKey::new([0x73; 16])?,
    );

    assert!(
        created.is_ok(),
        "tenant creation must not require a stale registry precondition"
    );
    Ok(())
}
