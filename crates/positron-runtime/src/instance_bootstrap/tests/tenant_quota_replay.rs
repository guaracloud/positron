use positron_domain::identity::TenantId;
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    Catalog, CatalogPublicationFault, ResourceAmounts, ResourceDimension, WorkClaim, WorkKind,
    with_catalog_publication_fault_after,
};

use super::super::{InitializationPlan, InstanceBootstrap};
use super::support::Roots;
use super::tenant_policy::tenant_administrator;
use crate::BootstrapFailureCode;

#[test]
fn quota_replay_returns_its_original_result_without_restoring_an_obsolete_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x76; 16])?;
    let first = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x77; 16])?,
        1,
        [1; 11],
    )?;
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(2)?,
        AdministrativeIdempotencyKey::new([0x78; 16])?,
        1,
        [3; 11],
    )?;
    let replay = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x77; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(replay, first);
    let reservation = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)?;
    drop(reservation);
    Ok(())
}

#[test]
fn changed_quota_request_reusing_an_idempotency_key_is_a_typed_conflict()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x79; 16])?;
    let key = AdministrativeIdempotencyKey::new([0x7a; 16])?;
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        key,
        1,
        [2; 11],
    )?;
    let failure = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            key,
            1,
            [3; 11],
        )
        .expect_err("changed request must not reuse an idempotency result");
    assert_eq!(
        failure.code(),
        BootstrapFailureCode::TenantQuotaIdempotencyConflict
    );
    Ok(())
}

#[test]
fn stale_quota_generation_returns_the_current_generation_without_quota_contents()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x7b; 16])?;
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x7c; 16])?,
        1,
        [2; 11],
    )?;
    let failure = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x7d; 16])?,
            1,
            [3; 11],
        )
        .expect_err("new requests must carry the current quota generation");
    assert_eq!(
        failure.code(),
        BootstrapFailureCode::TenantQuotaStaleGeneration
    );
    assert_eq!(
        failure
            .quota_generation_conflict()
            .map(ResourceGeneration::get),
        Some(2)
    );
    Ok(())
}

#[test]
fn quota_update_is_durable_across_restart_and_rejects_invalid_prepublication_input()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x7e; 16])?;
    let invalid = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x7f; 16])?,
            0,
            [1; 11],
        )
        .expect_err("invalid quota must not publish");
    assert_eq!(invalid.code(), BootstrapFailureCode::CatalogUnavailable);
    initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x80; 16])?,
        1,
        [1; 11],
    )?;
    drop(initialized);
    let reopened = InstanceBootstrap::reopen(&paths)?;
    let failure = reopened
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            reopened.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("restart must reconstruct the published quota");
    assert_eq!(
        failure.code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    Ok(())
}

#[test]
fn quota_update_rejects_wrong_scope_and_tenant_without_publishing()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let ingest = initialized.attribute(
        PresentedCredential::parse(claim.ingest_secret().ok_or("ingest key")?)?,
        RequestedIntent::Ingest,
        CompatibilityHints::none(),
    )?;
    let wrong_scope = initialized
        .update_tenant_quota(
            ingest,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x81; 16])?,
            1,
            [1; 11],
        )
        .expect_err("ingest scope cannot administer a quota");
    assert_eq!(
        wrong_scope.code(),
        BootstrapFailureCode::TenantQuotaUnauthorized
    );
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let wrong_tenant = initialized
        .update_tenant_quota(
            system,
            TenantId::from_bytes([0x82; 16])?,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x83; 16])?,
            1,
            [1; 11],
        )
        .expect_err("a system principal must still name an existing tenant");
    assert_eq!(
        wrong_tenant.code(),
        BootstrapFailureCode::TenantQuotaUnauthorized
    );
    Ok(())
}

#[test]
fn failed_quota_catalog_publication_preserves_the_durable_and_live_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x84; 16])?;
    let failure =
        with_catalog_publication_fault_after(CatalogPublicationFault::SynchronizeCommit, 0, || {
            initialized.update_tenant_quota(
                actor,
                initialized.tenant,
                ResourceGeneration::new(1).expect("known valid generation"),
                AdministrativeIdempotencyKey::new([0x85; 16]).expect("known valid key"),
                1,
                [1; 11],
            )
        })
        .expect_err("commit synchronization fault must reject quota publication");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let (_, governance) = catalog.pin()?.governance_object()?;
    assert_eq!(governance.quota_generation(), 1);
    let reservation = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)?;
    drop(reservation);
    Ok(())
}
