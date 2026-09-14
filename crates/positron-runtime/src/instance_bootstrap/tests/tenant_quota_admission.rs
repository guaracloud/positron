use positron_domain::identity::{Scope, TenantId, TenantSlug};
use positron_governance::{
    AdministrativeIdempotencyKey, CompatibilityHints, PresentedCredential, RequestedIntent,
    ResourceGeneration,
};
use positron_kernel::{
    Catalog, CatalogObject, CatalogProposal, FormatEpoch, ResourceAmounts, ResourceDimension,
    TransactionId, WorkClaim, WorkKind,
};

use super::super::{InitializationPlan, InstanceBootstrap, resources};
use super::support::Roots;
use super::tenant_policy::tenant_administrator;
use crate::BootstrapFailureCode;

#[test]
fn reopened_instance_applies_the_current_durable_quota_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let snapshot = catalog.pin()?;
    let (_, governance) = snapshot.governance_object()?;
    let mut objects = Vec::new();
    for object in snapshot.object_identities() {
        let bytes = snapshot.object(object)?.ok_or("catalog object")?;
        if !bytes.starts_with(b"POSGOV") {
            objects.push(CatalogObject::new(bytes.to_vec())?);
        }
    }
    objects.push(CatalogObject::new(governance.with_quota(2, 1, [1; 11])?)?);
    catalog.commit(
        snapshot.identity(),
        CatalogProposal::new(
            TransactionId::new([0x73; 16])?,
            FormatEpoch::CATALOG_V1,
            objects,
        )?,
        None,
    )?;
    drop(catalog);
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
        .expect_err("the persisted quota must limit admission after reopen");
    assert_eq!(
        failure.code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    Ok(())
}

#[test]
fn tenant_administrator_publishes_a_quota_that_immediately_limits_new_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant_key = initialized.create_api_key(
        system,
        Scope::TenantAdministration,
        None,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x74; 16])?,
    )?;
    let tenant_secret = tenant_key.secret().ok_or("tenant key")?.to_owned();
    let actor = initialized.attribute(
        PresentedCredential::parse(&tenant_secret)?,
        RequestedIntent::TenantAdministration,
        CompatibilityHints::none(),
    )?;
    let update = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x75; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(update.resource_generation().get(), 2);
    let replay = initialized.update_tenant_quota(
        actor,
        initialized.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x75; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(replay, update);
    let failure = initialized
        ._authority
        .governor()
        .reserve(WorkClaim::tenant(
            initialized.tenant,
            WorkKind::Ingest,
            ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
        )?)
        .expect_err("the committed quota must limit new admission");
    assert_eq!(
        failure.code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    let audit = initialized
        .governance_audit_for_test()?
        .into_iter()
        .find(|audit| audit.position() == update.audit_position())
        .ok_or("quota audit")?;
    assert_eq!(audit.action(), "tenant-quota.update");
    assert_eq!(audit.outcome(), "succeeded");
    let quota = audit.as_tenant_quota_update().ok_or("quota audit type")?;
    assert_eq!(quota.principal_id(), actor.principal_id());
    assert_eq!(quota.tenant_id(), initialized.tenant);
    assert_eq!(quota.expected_generation().get(), 1);
    assert_eq!(quota.generation().get(), 2);
    assert_eq!(quota.weight(), 1);
    assert_eq!(quota.resources(), [1; 11]);
    assert_eq!(quota.idempotency_key().to_bytes(), [0x75; 16]);
    assert_ne!(quota.request_digest(), [0; 32]);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    let replay_after_reopen = reopened.update_tenant_quota(
        reopened.attribute(
            PresentedCredential::parse(&tenant_secret)?,
            RequestedIntent::TenantAdministration,
            CompatibilityHints::none(),
        )?,
        reopened.tenant,
        ResourceGeneration::new(1)?,
        AdministrativeIdempotencyKey::new([0x75; 16])?,
        1,
        [1; 11],
    )?;
    assert_eq!(replay_after_reopen, update);
    assert_eq!(
        reopened
            ._authority
            .governor()
            .reserve(WorkClaim::tenant(
                reopened.tenant,
                WorkKind::Ingest,
                ResourceAmounts::only(ResourceDimension::MemoryBytes, 2)?,
            )?)
            .expect_err("an exact retry after reopen must reconcile the committed live limit")
            .code(),
        positron_kernel::AdmissionFailureCode::TenantQuotaExceeded
    );
    Ok(())
}

#[test]
fn quota_above_the_ordinary_ceiling_is_rejected_before_durable_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    let initialized = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    drop(initialized);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen(&paths)?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x94; 16])?;
    let key = AdministrativeIdempotencyKey::new([0x95; 16])?;
    let audit_before = initialized.governance_audit_for_test()?;
    for _ in 0..2 {
        let failure = initialized
            .update_tenant_quota(
                actor,
                initialized.tenant,
                ResourceGeneration::new(1)?,
                key,
                2,
                [u64::MAX; 11],
            )
            .expect_err("above-ceiling quota must not publish");
        assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    }
    assert_eq!(initialized.governance_audit_for_test()?, audit_before);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen(&paths)?;
    assert_eq!(reopened.governance_audit_for_test()?, audit_before);
    Ok(())
}

#[test]
fn unequal_weight_that_starves_a_recovery_tenant_rejects_before_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        2,
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 2)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    initialized.create_tenant(
        system,
        TenantId::from_bytes([0x96; 16])?,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("recovery-peer")?,
            "Recovery peer",
            2_592_000,
            1,
            resources::initial_tenant_quota(),
        ),
        AdministrativeIdempotencyKey::new([0x97; 16])?,
    )?;
    let actor = tenant_administrator(&initialized, claim.secret(), [0x98; 16])?;
    let audit_before = initialized.governance_audit_for_test()?;

    let failure = initialized
        .update_tenant_quota(
            actor,
            initialized.tenant,
            ResourceGeneration::new(1)?,
            AdministrativeIdempotencyKey::new([0x99; 16])?,
            2,
            resources::initial_tenant_quota(),
        )
        .expect_err("a candidate that gives its recovery peer a zero fair share must not publish");
    assert_eq!(failure.code(), BootstrapFailureCode::CatalogUnavailable);
    assert_eq!(
        initialized.governance_audit_for_test()?,
        audit_before,
        "a rejected candidate must not publish an audit outcome"
    );
    let catalog = Catalog::open(
        &initialized._authority,
        initialized.instance,
        initialized.key.catalog_secret(initialized.instance)?,
    )?;
    let (_, governance) = catalog.pin()?.governance_object()?;
    assert_eq!(governance.quota_generation(), 1);
    assert_eq!(governance.quota_weight(), 1);
    Ok(())
}

#[test]
fn created_weighted_tenant_has_the_same_live_fair_boundary_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = Roots::new()?;
    let paths = roots.paths();
    drop(InstanceBootstrap::initialize_with_max_registered_tenants(
        &paths,
        InitializationPlan::non_interactive(),
        3,
    )?);
    let claim = InstanceBootstrap::claim(&paths)?;
    let initialized = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 3)?;
    let system = initialized.attribute(
        PresentedCredential::parse(claim.secret())?,
        RequestedIntent::SystemAdministration,
        CompatibilityHints::none(),
    )?;
    let tenant = TenantId::from_bytes([0x9a; 16])?;
    initialized.create_tenant(
        system,
        tenant,
        positron_governance::TenantCreateConfiguration::new(
            TenantSlug::parse_canonical("weighted-peer")?,
            "Weighted peer",
            2_592_000,
            2,
            resources::initial_tenant_quota(),
        ),
        AdministrativeIdempotencyKey::new([0x9b; 16])?,
    )?;
    let claim = WorkClaim::tenant(
        tenant,
        WorkKind::Ingest,
        ResourceAmounts::only(ResourceDimension::FileDescriptors, 28)?,
    )?;
    let reservation = initialized
        ._authority
        .governor()
        .reserve(claim)
        .expect("weight two must receive its 2/3 fair share immediately after creation");
    drop(reservation);
    drop(initialized);

    let reopened = InstanceBootstrap::reopen_with_max_registered_tenants(&paths, 3)?;
    let reservation = reopened
        ._authority
        .governor()
        .reserve(claim)
        .expect("reopen must reconstruct the same durable weight-two fair boundary");
    drop(reservation);
    Ok(())
}
